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

#include "osquery/core/test_util.h"
#include "osquery/logger/plugins/aws_kinesis.h"

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

class KinesisTests : public testing::Test {};

TEST_F(KinesisTests, test_send) {
  KinesisLogForwarder forwarder;
  forwarder.shard_id_ = "fake_shard_id";
  auto client = std::make_shared<StrictMock<MockKinesisClient>>();
  forwarder.client_ = client;

  std::vector<std::string> logs{"foo"};
  Aws::Kinesis::Model::PutRecordsOutcome outcome;
  outcome.GetResult().SetFailedRecordCount(0);
  EXPECT_CALL(
      *client,
      PutRecords(Property(&Aws::Kinesis::Model::PutRecordsRequest::GetRecords,
                          ElementsAre(MatchesEntry("foo", "fake_shard_id")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(0), forwarder.send(logs, "results"));

  logs = {"bar", "foo"};
  Aws::Kinesis::Model::PutRecordsResultEntry entry;
  outcome.GetResult().AddRecords(entry);
  entry.SetErrorCode("foo");
  entry.SetErrorMessage("Foo error");
  outcome.GetResult().SetFailedRecordCount(1);
  outcome.GetResult().AddRecords(entry);

  EXPECT_CALL(
      *client,
      PutRecords(Property(&Aws::Kinesis::Model::PutRecordsRequest::GetRecords,
                          ElementsAre(MatchesEntry("bar", "fake_shard_id"),
                                      MatchesEntry("foo", "fake_shard_id")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(1, "Foo error"), forwarder.send(logs, "results"));
}
}
