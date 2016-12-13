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
#include <aws/firehose/model/DescribeDeliveryStreamRequest.h>
#include <aws/firehose/model/DescribeDeliveryStreamResult.h>
#include <aws/firehose/model/PutRecordBatchRequest.h>
#include <aws/firehose/model/PutRecordBatchResponseEntry.h>
#include <aws/firehose/model/PutRecordBatchResult.h>
#include <aws/firehose/model/Record.h>

#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/logger/plugins/aws_firehose.h"
#include "osquery/logger/plugins/aws_util.h"

namespace osquery {

REGISTER(FirehoseLoggerPlugin, "logger", "aws_firehose");

FLAG(uint64,
     aws_firehose_period,
     10,
     "Seconds between flushing logs to Firehose (default 10)");
FLAG(string, aws_firehose_stream, "", "Name of Firehose stream for logging")

// This is the max per AWS docs
const size_t FirehoseLogForwarder::kFirehoseMaxRecords = 500;
// Max size of log + partition key is 1MB. Max size of partition key is 256B.
const size_t FirehoseLogForwarder::kFirehoseMaxLogBytes = 1000000 - 256;

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

Status FirehoseLogForwarder::send(std::vector<std::string>& log_data,
                                  const std::string& log_type) {
  std::vector<Aws::Firehose::Model::Record> records;
  for (const std::string& log : log_data) {
    if (log.size() + 1 > kFirehoseMaxLogBytes) {
      LOG(ERROR) << "Firehose log too big, discarding!";
    }
    Aws::Firehose::Model::Record record;
    auto buffer =
        Aws::Utils::ByteBuffer((unsigned char*)log.c_str(), log.length() + 1);
    // Firehose buffers together the individual records, so we must insert
    // newlines here if we want newlines in the resultant files after Firehose
    // processing. See http://goo.gl/Pz6XOj
    buffer[log.length()] = '\n';
    record.SetData(buffer);
    records.push_back(std::move(record));
  }

  Aws::Firehose::Model::PutRecordBatchRequest request;
  request.WithDeliveryStreamName(FLAGS_aws_firehose_stream)
      .WithRecords(std::move(records));

  Aws::Firehose::Model::PutRecordBatchOutcome outcome =
      client_->PutRecordBatch(request);
  Aws::Firehose::Model::PutRecordBatchResult result = outcome.GetResult();
  if (result.GetFailedPutCount() != 0) {
    for (const auto& record : result.GetRequestResponses()) {
      if (!record.GetErrorMessage().empty()) {
        VLOG(1) << "Firehose write for " << result.GetFailedPutCount() << " of "
                << result.GetRequestResponses().size()
                << " records failed with error " << record.GetErrorMessage();
        return Status(1, record.GetErrorMessage());
      }
    }
  }

  VLOG(1) << "Successfully sent " << result.GetRequestResponses().size()
          << " logs to Firehose.";
  return Status(0);
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
  Aws::Firehose::Model::DescribeDeliveryStreamRequest r;
  r.SetDeliveryStreamName(FLAGS_aws_firehose_stream);
  VLOG(1) << "Firehose logging initialized with stream: "
          << FLAGS_aws_firehose_stream;
  return Status(0);
}
}
