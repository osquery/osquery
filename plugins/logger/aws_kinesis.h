/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "aws_log_forwarder.h"

#include <chrono>
#include <memory>
#include <vector>
#include <gflags/gflags.h>

#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>

#include <osquery/core/core.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/dispatcher/dispatcher.h>

namespace osquery {
DECLARE_uint64(aws_kinesis_period);

using IKinesisLogForwarder =
    AwsLogForwarder<Aws::Kinesis::Model::PutRecordsRequestEntry,
                    Aws::Kinesis::KinesisClient,
                    Aws::Kinesis::Model::PutRecordsOutcome,
                    Aws::Vector<Aws::Kinesis::Model::PutRecordsResultEntry>>;

class KinesisLogForwarder final : public IKinesisLogForwarder {
 public:
  KinesisLogForwarder(const std::string& name,
                      uint64_t log_period,
                      uint64_t max_lines,
                      const std::string& endpoint_override)
      : IKinesisLogForwarder(name, log_period, max_lines, endpoint_override) {}

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

  bool usesLogStatus() override;

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
