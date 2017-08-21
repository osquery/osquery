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

#include <boost/algorithm/string/join.hpp>

#include <aws/core/utils/Outcome.h>
#include <aws/firehose/model/PutRecordBatchRequest.h>
#include <aws/firehose/model/PutRecordBatchResponseEntry.h>
#include <aws/firehose/model/PutRecordBatchResult.h>
#include <aws/firehose/model/Record.h>

#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/logger/plugins/aws_firehose.h"
#include "osquery/utils/aws_util.h"

namespace osquery {

REGISTER(FirehoseLoggerPlugin, "logger", "aws_firehose");

FLAG(uint64,
     aws_firehose_period,
     10,
     "Seconds between flushing logs to Firehose (default 10)");

FLAG(string, aws_firehose_stream, "", "Name of Firehose stream for logging")

// This is the max per AWS docs
const size_t FirehoseLogForwarder::kFirehoseMaxRecords = 500;

// Max size of log is 1MB.
const size_t FirehoseLogForwarder::kFirehoseMaxLogBytes = 1000000;

// Max request size is 4MB.
const size_t FirehoseLogForwarder::kFirehoseMaxBatchBytes = 4000000;

// Used to split log data into batches compatible with the protocol limits
using FirehoseBatchGenerator = BatchGenerator<Aws::Firehose::Model::Record>;

Status FirehoseLoggerPlugin::setUp() {
  initAwsSdk();

  forwarder_ = std::make_shared<FirehoseLogForwarder>();
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing Firehose logger: " << s.getMessage();
    return s;
  }

  Dispatcher::addService(forwarder_);
  return Status(0);
}

Status FirehoseLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status FirehoseLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

void FirehoseLoggerPlugin::init(const std::string& name,
                                const std::vector<StatusLogLine>& log) {
  google::ShutdownGoogleLogging();
  google::InitGoogleLogging(name.c_str());
  logStatus(log);
}

Status FirehoseLogForwarder::send(std::vector<std::string>& log_data,
                                  const std::string& log_type) {
  // Generate the batches, according to the protocol limits
  //
  // Firehose buffers together the individual records, so we must insert
  // newlines here if we want newlines in the resultant files after Firehose
  // processing. See http://goo.gl/Pz6XOj
  StringList discarded_records;
  auto L_RecordInitializer = [](Aws::Firehose::Model::Record& record,
                                Aws::Utils::ByteBuffer& buffer) -> void {
    record.SetData(buffer);
  };

  auto batch_list =
      FirehoseBatchGenerator::consumeLogDataAndGenerate(discarded_records,
                                                        log_type,
                                                        log_data,
                                                        true,
                                                        kFirehoseMaxBatchBytes,
                                                        kFirehoseMaxLogBytes,
                                                        kFirehoseMaxRecords,
                                                        L_RecordInitializer);

  for (const auto& record : discarded_records) {
    LOG(ERROR) << "aws_firehose: The following log record has been discarded "
                  "because it was too big: "
               << record;
  }

  discarded_records.clear();

  // Send each batch
  std::size_t sent_record_count = 0U;
  bool send_error = false;

  for (auto& batch : batch_list) {
    Aws::Firehose::Model::PutRecordBatchRequest request;
    request.WithDeliveryStreamName(FLAGS_aws_firehose_stream)
        .WithRecords(std::move(batch));

    Aws::Firehose::Model::PutRecordBatchOutcome outcome =
        client_->PutRecordBatch(request);

    if (!outcome.IsSuccess()) {
      LOG(ERROR) << "Firehose write failed: "
                 << outcome.GetError().GetMessage();

      send_error = true;
      continue;
    }

    Aws::Firehose::Model::PutRecordBatchResult result = outcome.GetResult();
    sent_record_count += result.GetRequestResponses().size();

    if (result.GetFailedPutCount() == 0) {
      continue;
    }

    for (const auto& record : result.GetRequestResponses()) {
      if (record.GetErrorMessage().empty()) {
        continue;
      }

      VLOG(1) << "Firehose write for " << result.GetFailedPutCount() << " of "
              << result.GetRequestResponses().size()
              << " records failed with error " << record.GetErrorMessage();

      send_error = true;
    }
  }

  VLOG(1) << "Successfully sent " << sent_record_count << " logs to Firehose";

  return Status(send_error ? 1 : 0, "One or more records couldn't be written");
}

Status FirehoseLogForwarder::setUp() {
  Status s = BufferedLogForwarder::setUp();
  if (!s.ok()) {
    return s;
  }

  // Set up client
  s = makeAWSClient<Aws::Firehose::FirehoseClient>(client_);
  if (!s.ok()) {
    return s;
  }

  if (FLAGS_aws_firehose_stream.empty()) {
    return Status(1,
                  "Stream name must be specified with --aws_firehose_stream");
  }

  // Make sure we can connect to designated stream
  VLOG(1) << "Firehose logging initialized with stream: "
          << FLAGS_aws_firehose_stream;
  return Status(0);
}
}
