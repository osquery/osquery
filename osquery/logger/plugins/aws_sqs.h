/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <chrono>
#include <memory>
#include <vector>

#include <aws/sqs/SQSClient.h>
#include <aws/sqs/model/SendMessageBatchRequestEntry.h>
#include <aws/sqs/model/Message.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/aws_log_forwarder.h"

namespace osquery {
DECLARE_uint64(aws_sqs_period);

using ISQSLogForwarder =
    AwsLogForwarder<Aws::SQS::Model::Message,
                    Aws::SQS::SQSClient,
                    Aws::SQS::Model::SendMessageBatchOutcome,
                    Aws::Vector<Aws::SQS::Model::SendMessageBatchResultEntry>>;

class SQSLogForwarder final : public ISQSLogForwarder {
 public:
  SQSLogForwarder(const std::string& name,
                  size_t log_period,
                  size_t max_lines)
      : ISQSLogForwarder(name, log_period, max_lines) {}

 protected:
  Status internalSetup() override;
  Outcome internalSend(const Batch& batch) override;
  void initializeRecord(Record& record,
                        Aws::Utils::ByteBuffer& buffer) const override;

  size_t getMaxBytesPerRecord() const override;
  size_t getMaxRecordsPerBatch() const override;
  size_t getMaxBytesPerBatch() const override;
  size_t getMaxRetryCount() const override;
  size_t getInitialRetryDelay() const override;
  bool appendNewlineSeparators() const override;

  size_t getFailedRecordCount(Outcome& outcome) const override;
  Result getResult(Outcome& outcome) const override;

 private:
  FRIEND_TEST(SQSTests, test_send);
};

class SQSLoggerPlugin : public LoggerPlugin {
 public:
  SQSLoggerPlugin() : LoggerPlugin() {}

  Status setUp() override;

  bool usesLogStatus() override {
    return true;
  }

 private:
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  Status logString(const std::string& s) override;

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  std::shared_ptr<SQSLogForwarder> forwarder_{nullptr};
};
}
