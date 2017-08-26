/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <chrono>
#include <memory>
#include <vector>

#include <aws/firehose/FirehoseClient.h>
#include <aws/firehose/model/PutRecordBatchResponseEntry.h>
#include <aws/firehose/model/Record.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/aws_log_forwarder.h"

namespace osquery {

DECLARE_uint64(aws_firehose_period);

using IFirehoseLogForwarder = AwsLogForwarder<
    Aws::Firehose::Model::Record,
    Aws::Firehose::FirehoseClient,
    Aws::Firehose::Model::PutRecordBatchOutcome,
    Aws::Vector<Aws::Firehose::Model::PutRecordBatchResponseEntry>>;

class FirehoseLogForwarder final : public IFirehoseLogForwarder {
 public:
  FirehoseLogForwarder(const std::string& name,
                       size_t log_period,
                       size_t max_lines)
      : IFirehoseLogForwarder(name, log_period, max_lines) {}

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
  FRIEND_TEST(FirehoseTests, test_send);
};

class FirehoseLoggerPlugin : public LoggerPlugin {
 public:
  FirehoseLoggerPlugin() : LoggerPlugin() {}

  Status setUp() override;

  bool usesLogStatus() override {
    return true;
  }

 protected:
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  Status logString(const std::string& s) override;

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  std::shared_ptr<FirehoseLogForwarder> forwarder_{nullptr};
};
}
