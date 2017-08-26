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

#include <aws/kinesis/KinesisClient.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/aws_log_forwarder.h"

namespace osquery {
DECLARE_uint64(aws_kinesis_period);

class KinesisLogForwarder final : public IKinesisLogForwarder {
 public:
  KinesisLogForwarder(const std::string& name,
                      size_t log_period,
                      size_t max_lines)
      : IKinesisLogForwarder(name, log_period, max_lines) {}

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
  /// The partition key; ignored if aws_kinesis_random_partition_key is set
  std::string partition_key_;

  FRIEND_TEST(KinesisTests, test_send);
};

class KinesisLoggerPlugin : public LoggerPlugin {
 public:
  KinesisLoggerPlugin() : LoggerPlugin() {}

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
  std::shared_ptr<KinesisLogForwarder> forwarder_{nullptr};
};
}
