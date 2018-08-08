/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <aws/core/client/AWSError.h>
#include <aws/core/utils/Outcome.h>
#include <aws/sqs/model/SendMessageBatchRequest.h>
#include <aws/sqs/model/SendMessageBatchResult.h>

#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/logger/plugins/aws_sqs.h"

namespace osquery {

static const char* kAwsSQSServiceName = "aws_sqs";

REGISTER(SQSLoggerPlugin, "logger", kAwsSQSServiceName);

FLAG(uint64,
     aws_sqs_period,
     10,
     "Seconds between flushing logs to SQS (default 10)");

FLAG(string, aws_sqs_queue_url, "", "URL of SQS queue for logging")

Status SQSLoggerPlugin::setUp() {
  initAwsSdk();
  forwarder_ = std::make_shared<SQSLogForwarder>(
      kAwsSQSServiceName, aws_sqs_queue_url, 500);
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing SQS logger: " << s.getMessage();
    return s;
  }

  s = Dispatcher::addService(forwarder_);
  if (!s.ok()) {
    LOG(ERROR) << "Error adding SQS dispatcher service: " << s.getMessage();
    return s;
  }

  return Status::success();
}

Status SQSLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status SQSLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

void SQSLoggerPlugin::init(const std::string& name,
                           const std::vector<StatusLogLine>& log) {
  logStatus(log);
}

Status SQSLogForwarder::internalSetup() {
  if (FLAGS_aws_sqs_queue_url.empty()) {
    return Status::failure("Queue URL must be specified with --aws_sqs_queue_url");
  }

  VLOG(1) << "SQS logging initialized with queue URL: "
          << FLAGS_aws_sqs_queue_url;

  return Status::success();
}

SQSLogForwarder::Outcome SQSLogForwarder::internalSend(
    const Batch& batch) {
  Aws::SQS::Model::SendMessageBatchRequest request;
  request.WithQueueUrl(FLAGS_aws_sqs_queue_url).SetEntries(batch);
  return client_->SendMessageBatch(request);
}

void SQSLogForwarder::initializeRecord(
    Record& record, Aws::Utils::ByteBuffer& buffer) const {
  record.SetBody(buffer);
}

size_t SQSLogForwarder::getMaxBytesPerRecord() const {
  return 262144U;
}

size_t SQSLogForwarder::getMaxRecordsPerBatch() const {
  return 10U;
}

size_t SQSLogForwarder::getMaxBytesPerBatch() const {
  return 262144U;
}

size_t SQSLogForwarder::getMaxRetryCount() const {
  return 100U;
}

size_t SQSLogForwarder::getInitialRetryDelay() const {
  return 3000U;
}

bool SQSLogForwarder::appendNewlineSeparators() const {
  return false;
}

size_t SQSLogForwarder::getFailedRecordCount(Outcome& outcome) const {
  return static_cast<size_t>(outcome.GetResult().GetFailed());
}

SQSLogForwarder::Result SQSLogForwarder::getResult(
    Outcome& outcome) const {
  return outcome.GetResult().GetEntries();
}
}
