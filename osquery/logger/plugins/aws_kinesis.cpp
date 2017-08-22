/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <chrono>
#include <iterator>
#include <thread>

#include <aws/core/utils/Outcome.h>
#include <aws/kinesis/model/PutRecordsRequest.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>
#include <aws/kinesis/model/PutRecordsResult.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/logger/plugins/aws_kinesis.h"
#include "osquery/utils/aws_util.h"

namespace osquery {

REGISTER(KinesisLoggerPlugin, "logger", "aws_kinesis");

FLAG(uint64,
     aws_kinesis_period,
     10,
     "Seconds between flushing logs to Kinesis (default 10)");

FLAG(string, aws_kinesis_stream, "", "Name of Kinesis stream for logging")

FLAG(bool,
     aws_kinesis_random_partition_key,
     false,
     "Enable random kinesis partition keys");

// Used to split log data into batches compatible with the protocol limits
using KinesisBatchGenerator =
    BatchGenerator<Aws::Kinesis::Model::PutRecordsRequestEntry>;

// This is the max per AWS docs
const size_t KinesisLogForwarder::kKinesisMaxRecordsPerBatch = 500;

// Max batch size
const size_t KinesisLogForwarder::kKinesisMaxBytesPerBatch = 5000000;

// Max size of log + partition key is 1MB. Max size of partition key is 256B.
const size_t KinesisLogForwarder::kKinesisMaxBytesPerRecord = 1000000 - 256;

const size_t KinesisLogForwarder::kKinesisMaxRetryCount = 100;
const size_t KinesisLogForwarder::kKinesisInitialRetryDelay = 3000;

Status KinesisLoggerPlugin::setUp() {
  initAwsSdk();
  forwarder_ = std::make_shared<KinesisLogForwarder>();
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing Kinesis logger: " << s.getMessage();
    return s;
  }
  Dispatcher::addService(forwarder_);
  return Status(0, "OK");
}

Status KinesisLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status KinesisLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

void KinesisLoggerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {
  google::ShutdownGoogleLogging();
  google::InitGoogleLogging(name.c_str());
  logStatus(log);
}

Status KinesisLogForwarder::send(std::vector<std::string>& log_data,
                                 const std::string& log_type) {
  // Generate the batches, according to the protocol limits
  StringList discarded_records;
  auto L_RecordInitializer = [this](
      Aws::Kinesis::Model::PutRecordsRequestEntry& record,
      Aws::Utils::ByteBuffer& buffer) -> void {

    std::string record_partition_key;
    if (FLAGS_aws_kinesis_random_partition_key) {
      // Generate a random partition key for each record, ensuring that
      // records are spread evenly across shards.
      boost::uuids::uuid uuid = boost::uuids::random_generator()();
      record_partition_key = boost::uuids::to_string(uuid);
    } else {
      record_partition_key = partition_key_;
    }

    Aws::Kinesis::Model::PutRecordsRequestEntry entry;
    record.WithPartitionKey(record_partition_key).WithData(buffer);
  };

  auto batch_list = KinesisBatchGenerator::consumeLogDataAndGenerate(
      discarded_records,
      log_type,
      log_data,
      true,
      kKinesisMaxBytesPerBatch,
      kKinesisMaxBytesPerRecord,
      kKinesisMaxRecordsPerBatch,
      L_RecordInitializer);

  for (const auto& record : discarded_records) {
    LOG(ERROR) << "aws_kinesis: The following log record has been discarded "
                  "because it was too big: "
               << record;
  }

  discarded_records.clear();

  // Send each batch
  std::size_t sent_record_count = 0U;

  for (auto batch_it = batch_list.begin(); batch_it != batch_list.end();) {
    auto& batch = *batch_it;
    bool send_error = true;

    for (std::size_t retry = 0; retry < kKinesisMaxRetryCount; retry++) {
      // Increase the resend delay at each retry
      std::size_t retry_delay =
          (retry == 0 ? 0 : kKinesisInitialRetryDelay) + (retry * 1000U);
      if (retry_delay != 0) {
        std::this_thread::sleep_for(std::chrono::seconds(retry_delay));
      }

      // Attempt to send the whole batch
      Aws::Kinesis::Model::PutRecordsRequest request;
      request.WithStreamName(FLAGS_aws_kinesis_stream).SetRecords(batch);

      auto outcome = client_->PutRecords(request);
      if (!outcome.IsSuccess()) {
        LOG(ERROR) << "Kinesis write failed: "
                   << outcome.GetError().GetMessage();
        continue;
      }

      auto result = outcome.GetResult();
      VLOG(1) << "Successfully sent "
              << result.GetRecords().size() - result.GetFailedRecordCount()
              << " of " << result.GetRecords().size() << " logs to Kinesis";

      if (result.GetFailedRecordCount() == 0) {
        send_error = false;
        break;
      }

      // We didn't manage to send all records; remove the ones that succeeded
      // (so that we do not duplicate them) and try again
      std::size_t record_index = 0;
      for (const auto& record : result.GetRecords()) {
        if (!record.GetErrorCode().empty()) {
          batch.erase(std::next(batch.begin(), record_index));
        }

        record_index++;
      }
    }

    // We couldn't write some of the records; log them locally so that the
    // administrator will at least be able to inspect them
    if (send_error) {
      LOG(ERROR) << "The aws_kinesis logger failed to send the following "
                 << batch.size() << " log records: ";
      for (const auto& failed_record : batch) {
        const auto& record_data = failed_record.GetData();
        LOG(ERROR) << " > " << std::string(reinterpret_cast<const char*>(
                                               record_data.GetUnderlyingData()),
                                           record_data.GetLength());
      }
    }

    batch_it = batch_list.erase(batch_it);
  }

  return Status(0, "OK");
}

Status KinesisLogForwarder::setUp() {
  Status s = BufferedLogForwarder::setUp();
  if (!s.ok()) {
    return s;
  }

  // Set up client
  s = makeAWSClient<Aws::Kinesis::KinesisClient>(client_);
  if (!s.ok()) {
    return s;
  }

  partition_key_ = getHostIdentifier();

  if (FLAGS_aws_kinesis_stream.empty()) {
    return Status(1, "Stream name must be specified with --aws_kinesis_stream");
  }

  VLOG(1) << "Kinesis logging initialized with stream: "
          << FLAGS_aws_kinesis_stream;
  return Status(0);
}
}
