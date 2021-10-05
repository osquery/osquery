/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "aws_firehose.h"

#include <algorithm>

#include <boost/algorithm/string/join.hpp>

#include <aws/core/client/AWSError.h>
#include <aws/core/utils/Outcome.h>
#include <aws/firehose/model/PutRecordBatchRequest.h>
#include <aws/firehose/model/PutRecordBatchResult.h>

#include <osquery/core/flags.h>
#include <osquery/registry/registry.h>

namespace osquery {

REGISTER(FirehoseLoggerPlugin, "logger", "aws_firehose");

FLAG(uint64,
     aws_firehose_period,
     10,
     "Seconds between flushing logs to Firehose (default 10)");

FLAG(string, aws_firehose_stream, "", "Name of Firehose stream for logging")

FLAG(string, aws_firehose_endpoint, "", "Custom Firehose endpoint");

Status FirehoseLoggerPlugin::setUp() {
  initAwsSdk();

  forwarder_ =
      std::make_shared<FirehoseLogForwarder>("aws_firehose",
                                             FLAGS_aws_firehose_period,
                                             500,
                                             FLAGS_aws_firehose_endpoint);
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

size_t FirehoseLogForwarder::getMaxBytesPerRecord() const {
  return 1000000U;
}

size_t FirehoseLogForwarder::getMaxRecordsPerBatch() const {
  return 500U;
}

size_t FirehoseLogForwarder::getMaxBytesPerBatch() const {
  return 4000000U;
}

size_t FirehoseLogForwarder::getMaxRetryCount() const {
  return 100U;
}

size_t FirehoseLogForwarder::getInitialRetryDelay() const {
  return 3000U;
}

bool FirehoseLogForwarder::appendNewlineSeparators() const {
  return true;
}

size_t FirehoseLogForwarder::getFailedRecordCount(Outcome& outcome) const {
  return static_cast<size_t>(outcome.GetResult().GetFailedPutCount());
}

FirehoseLogForwarder::Result FirehoseLogForwarder::getResult(
    Outcome& outcome) const {
  return outcome.GetResult().GetRequestResponses();
}
}
