/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <aws/core/utils/Outcome.h>
#include <aws/kinesis/model/PutRecordsRequest.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>
#include <aws/kinesis/model/PutRecordsResult.h>

#include <osquery/logger.h>

#include "osquery/logger/plugins/aws_kinesis.h"
#include "osquery/logger/plugins/aws_util.h"
#include "osquery/tests/test_util.h"

using namespace testing;

namespace osquery {

// Match on just the partition key and data elements of a PutRecordsRequestEntry
MATCHER_P2(MatchesEntry, data, key, "") {
  return arg.GetPartitionKey() == key &&
         data == std::string(
                     reinterpret_cast<char*>(arg.GetData().GetUnderlyingData()),
                     arg.GetData().GetLength());
}

class MockKinesisClient : public Aws::Kinesis::KinesisClient {
 public:
  MOCK_CONST_METHOD1(
      PutRecords,
      Aws::Kinesis::Model::PutRecordsOutcome(
          const Aws::Kinesis::Model::PutRecordsRequest& request));
};

class KinesisTests : public testing::Test {
 public:
  void SetUp() override { initAwsSdk(); }
};

TEST_F(KinesisTests, test_send) {
  KinesisLogForwarder forwarder;
  forwarder.partition_key_ = "fake_partition_key";
  auto client = std::make_shared<StrictMock<MockKinesisClient>>();
  forwarder.client_ = client;

  std::vector<std::string> logs{"{\"foo\":\"bar\"}"};
  Aws::Kinesis::Model::PutRecordsOutcome outcome;
  outcome.GetResult().SetFailedRecordCount(0);
  EXPECT_CALL(
      *client,
      PutRecords(Property(
          &Aws::Kinesis::Model::PutRecordsRequest::GetRecords,
          ElementsAre(MatchesEntry("{\"foo\":\"bar\",\"log_type\":\"results\"}",
                                   "fake_partition_key")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(0), forwarder.send(logs, "results"));

  logs = {"{\"bar\":\"foo\"}", "{\"foo\":\"bar\"}"};
  Aws::Kinesis::Model::PutRecordsResultEntry entry;
  outcome.GetResult().AddRecords(entry);
  entry.SetErrorCode("foo");
  entry.SetErrorMessage("Foo error");
  outcome.GetResult().SetFailedRecordCount(2);
  outcome.GetResult().AddRecords(entry);

  EXPECT_CALL(
      *client,
      PutRecords(Property(
          &Aws::Kinesis::Model::PutRecordsRequest::GetRecords,
          ElementsAre(MatchesEntry("{\"bar\":\"foo\",\"log_type\":\"results\"}",
                                   "fake_partition_key"),
                      MatchesEntry("{\"foo\":\"bar\",\"log_type\":\"results\"}",
                                   "fake_partition_key")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(1, "Foo error"), forwarder.send(logs, "results"));
}
}
