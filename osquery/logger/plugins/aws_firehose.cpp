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
#include <aws/firehose/model/PutRecordBatchResult.h>

#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/logger/plugins/aws_firehose.h"

namespace osquery {

REGISTER(FirehoseLoggerPlugin, "logger", "aws_firehose");

FLAG(uint64,
     aws_firehose_period,
     10,
     "Seconds between flushing logs to Firehose (default 10)");

FLAG(string, aws_firehose_stream, "", "Name of Firehose stream for logging")

Status FirehoseLoggerPlugin::setUp() {
  initAwsSdk();

  forwarder_ = std::make_shared<FirehoseLogForwarder>(
      "aws_firehose", FLAGS_aws_firehose_period, 500);
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
Status FirehoseLogForwarder::internalSetup() {
  if (FLAGS_aws_firehose_stream.empty()) {
    return Status(1,
                  "Stream name must be specified with --aws_firehose_stream");
  }

  // Make sure we can connect to designated stream
  VLOG(1) << "Firehose logging initialized with stream: "
          << FLAGS_aws_firehose_stream;
  return Status(0);
}

FirehoseLogForwarder::Outcome FirehoseLogForwarder::internalSend(
    const Batch& batch) {
  Aws::Firehose::Model::PutRecordBatchRequest request;
  request.WithDeliveryStreamName(FLAGS_aws_firehose_stream)
      .WithRecords(std::move(batch));
  return client_->PutRecordBatch(request);
}

void FirehoseLogForwarder::initializeRecord(
    Record& record, Aws::Utils::ByteBuffer& buffer) const {
  record.SetData(buffer);
}

std::size_t FirehoseLogForwarder::getFailedRecordCount(Outcome& outcome) const {
  return static_cast<std::size_t>(outcome.GetResult().GetFailedPutCount());
}

FirehoseLogForwarder::Result FirehoseLogForwarder::getResult(
    Outcome& outcome) const {
  return outcome.GetResult().GetRequestResponses();
}
}
