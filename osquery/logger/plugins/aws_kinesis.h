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

#include "osquery/logger/plugins/buffered.h"

namespace osquery {

DECLARE_uint64(aws_kinesis_period);

class KinesisLogForwarder : public BufferedLogForwarder {
 private:
  static const size_t kKinesisMaxLogBytes;
  static const size_t kKinesisMaxRecords;

 public:
  KinesisLogForwarder()
      : BufferedLogForwarder("kinesis",
                             std::chrono::seconds(FLAGS_aws_kinesis_period),
                             kKinesisMaxRecords) {}
  Status setUp() override;

 protected:
  Status send(std::vector<std::string>& log_data,
              const std::string& log_type) override;

 private:
  std::string partition_key_;
  std::shared_ptr<Aws::Kinesis::KinesisClient> client_{nullptr};

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
