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
#include "osquery/logger/plugins/aws_util.h"

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

// This is the max per AWS docs
const size_t KinesisLogForwarder::kKinesisMaxRecords = 500;

// Max size of log + partition key is 1MB. Max size of partition key is 256B.
const size_t KinesisLogForwarder::kKinesisMaxLogBytes = 1000000 - 256;

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
  size_t retry_count = kKinesisMaxRetryCount;
  size_t retry_delay = kKinesisInitialRetryDelay;
  size_t original_data_size = log_data.size();

  // exit if we sent all the data
  while (log_data.size() > 0) {
    std::vector<Aws::Kinesis::Model::PutRecordsRequestEntry> entries;
    std::vector<int> valid_log_data_indices;

    int i = 0;
    for (std::string& log : log_data) {
      if (retry_count == kKinesisMaxRetryCount) {
        // On first send attempt, append log_type to the JSON log content
        // Other send attempts will be already have log_type appended
        Status status = appendLogTypeToJson(log_type, log);
        if (!status.ok()) {
          LOG(ERROR)
              << "Failed to append log_type key to status log JSON in Kinesis";

          i++;
          continue;
        }
      }

      if (log.size() > kKinesisMaxLogBytes) {
        LOG(ERROR) << "Kinesis log too big, discarding!";
      }

      std::string record_partition_key = partition_key_;
      if (FLAGS_aws_kinesis_random_partition_key) {
        // Generate a random partition key for each record, ensuring that
        // records are spread evenly across shards.
        boost::uuids::uuid uuid = boost::uuids::random_generator()();
        record_partition_key = boost::uuids::to_string(uuid);
      }

      Aws::Kinesis::Model::PutRecordsRequestEntry entry;
      entry.WithPartitionKey(record_partition_key)
          .WithData(Aws::Utils::ByteBuffer((unsigned char*)log.c_str(),
                                           log.length()));
      entries.push_back(std::move(entry));
      valid_log_data_indices.push_back(i);

      i++;
    }

    Aws::Kinesis::Model::PutRecordsRequest request;
    request.WithStreamName(FLAGS_aws_kinesis_stream)
        .WithRecords(std::move(entries));

    Aws::Kinesis::Model::PutRecordsOutcome outcome =
        client_->PutRecords(request);
    Aws::Kinesis::Model::PutRecordsResult result = outcome.GetResult();
    VLOG(1) << "Successfully sent "
            << result.GetRecords().size() - result.GetFailedRecordCount()
            << " of " << result.GetRecords().size() << " logs to Kinesis";
    if (result.GetFailedRecordCount() != 0) {
      std::vector<std::string> resend;
      std::string error_msg = "";
      i = 0;
      for (const auto& record : result.GetRecords()) {
        if (!record.GetErrorMessage().empty()) {
          int log_data_index = valid_log_data_indices[i];
          resend.push_back(log_data[log_data_index]);
          error_msg = record.GetErrorMessage();
        }
        i++;
      }
      // exit if we have tried too many times
      // exit if all uploads fail right off the bat
      // note, this will go back to the default logger batch retry code
      if (retry_count == 0 ||
          static_cast<int>(original_data_size) ==
              result.GetFailedRecordCount()) {
        LOG(ERROR) << "Kinesis write for " << result.GetFailedRecordCount()
                   << " of " << result.GetRecords().size()
                   << " records failed with error " << error_msg;
        return Status(1, error_msg);
      }

      VLOG(1) << "Resending " << result.GetFailedRecordCount()
              << " records to Kinesis";
      log_data = resend;
      sleepFor(retry_delay);
    } else {
      log_data.clear();
    }
    --retry_count;
    retry_delay += 1000;
  }
  return Status(0);
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
