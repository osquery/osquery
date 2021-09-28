/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <iostream>
#include <memory>
#include <vector>

#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>
#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_interface.h>

#include "plugins/logger/aws_log_forwarder.h"
#include "plugins/logger/buffered.h"

using namespace testing;

namespace osquery {

class AwsLoggerTests : public testing::Test {
 protected:
  void SetUp() {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

class DummyOutcome final : public Aws::Kinesis::Model::PutRecordsOutcome {
 public:
  bool IsSuccess() {
    return true;
  }
};

using RawBatch = std::vector<std::string>;
using RawBatchList = std::vector<RawBatch>;

using IDummyLogForwarder =
    AwsLogForwarder<Aws::Kinesis::Model::PutRecordsRequestEntry,
                    Aws::Kinesis::KinesisClient,
                    DummyOutcome,
                    Aws::Vector<Aws::Kinesis::Model::PutRecordsResultEntry>>;

class DummyLogForwarder final : public IDummyLogForwarder {
 public:
  DummyLogForwarder()
      : IDummyLogForwarder("dummy", 10, 50, "http://example.com") {}

 protected:
  Status internalSetup() override {
    return Status(0, "OK");
  }

  Outcome internalSend(const Batch& batch) override {
    RawBatch raw_batch;

    for (const auto& record : batch) {
      std::string buffer(
          reinterpret_cast<const char*>(record.GetData().GetUnderlyingData()),
          record.GetData().GetLength());

      raw_batch.push_back(buffer);
    }

    emitted_batch_list_.push_back(raw_batch);

    return Outcome();
  }

  void initializeRecord(Record& record,
                        Aws::Utils::ByteBuffer& buffer) const override {
    record.SetData(buffer);
  }

  std::size_t getMaxBytesPerRecord() const override {
    return 80U;
  }

  std::size_t getMaxRecordsPerBatch() const override {
    return 3U;
  }

  std::size_t getMaxBytesPerBatch() const override {
    return 128U;
  }

  std::size_t getMaxRetryCount() const override {
    return 1U;
  }

  std::size_t getInitialRetryDelay() const override {
    return 0U;
  }

  bool appendNewlineSeparators() const override {
    return true;
  }

  std::size_t getFailedRecordCount(Outcome& outcome) const override {
    return 0U;
  }

  Result getResult(Outcome& outcome) const override {
    return outcome.GetResult().GetRecords();
  }

 public:
  RawBatchList emitted_batch_list_;

  FRIEND_TEST(AwsLoggerTests, test_send);
};

TEST_F(AwsLoggerTests, test_send) {
  DummyLogForwarder log_forwarder;

  // The following 3 lines fit nicely inside a single batch
  log_forwarder.logString("{ \"batch1\": \"1\" }");
  log_forwarder.logString("{ \"batch1\": \"2\" }");
  log_forwarder.logString("{ \"batch1\": \"3\" }");
  log_forwarder.check();

  // The following two lines will be discarded
  std::cout << "Emitting two lines that will be discarded..." << std::endl;
  log_forwarder.logString(
      "{ \"test\": \"This line will be discarded because too long according to "
      "the protocol\" }");

  log_forwarder.logString(
      "This line will be discarded because it is not in JSON format");

  log_forwarder.check();

  // The next 3 lines will be split in two because the whole batch size
  // is too big
  log_forwarder.logString(
      "{ \"batch2\": \"1\", \"test test test test test\": \"1\" }");
  log_forwarder.logString(
      "{ \"batch2\": \"2\", \"test test test test test\": \"2\" }");
  log_forwarder.logString("{ \"batch3\": \"3\" }");
  log_forwarder.check();

  //
  // Make sure we have sent the correct data. Remember that we have
  // requested to add newlines at the end of each record!
  //

  // We expect to have sent three batches
  EXPECT_EQ(log_forwarder.emitted_batch_list_.size(), 3U);

  // The first batch should contain 3 items
  auto first_batch = log_forwarder.emitted_batch_list_[0];
  EXPECT_EQ(first_batch.size(), 3U);

  EXPECT_EQ(first_batch[0], "{\"batch1\":\"1\",\"log_type\":\"result\"}\n");
  EXPECT_EQ(first_batch[1], "{\"batch1\":\"2\",\"log_type\":\"result\"}\n");
  EXPECT_EQ(first_batch[2], "{\"batch1\":\"3\",\"log_type\":\"result\"}\n");

  // The second batch should contain only one item, because it has been split
  auto second_batch = log_forwarder.emitted_batch_list_[1];
  EXPECT_EQ(second_batch.size(), 1U);

  EXPECT_EQ(second_batch[0],
            "{\"batch2\":\"1\",\"test test test test "
            "test\":\"1\",\"log_type\":\"result\"}\n");

  // The third and last batch should contain the remaining 2 items
  auto third_batch = log_forwarder.emitted_batch_list_[2];
  EXPECT_EQ(third_batch.size(), 2U);

  EXPECT_EQ(third_batch[0],
            "{\"batch2\":\"2\",\"test test test test "
            "test\":\"2\",\"log_type\":\"result\"}\n");
  EXPECT_EQ(third_batch[1], "{\"batch3\":\"3\",\"log_type\":\"result\"}\n");
}
}
