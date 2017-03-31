/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <aws/core/utils/Outcome.h>
#include <aws/firehose/model/PutRecordBatchRequest.h>
#include <aws/firehose/model/PutRecordBatchResponseEntry.h>
#include <aws/firehose/model/PutRecordBatchResult.h>

#include <osquery/logger.h>

#include "osquery/tests/test_util.h"
#include "osquery/logger/plugins/aws_firehose.h"
#include "osquery/logger/plugins/aws_util.h"

using namespace testing;

namespace osquery {

// Match on just the data element of a PutRecordBatchEntry
MATCHER_P(MatchesEntry, data, "") {
  return data ==
         std::string(reinterpret_cast<char*>(arg.GetData().GetUnderlyingData()),
                     arg.GetData().GetLength());
}

class MockFirehoseClient : public Aws::Firehose::FirehoseClient {
 public:
  MOCK_CONST_METHOD1(
      PutRecordBatch,
      Aws::Firehose::Model::PutRecordBatchOutcome(
          const Aws::Firehose::Model::PutRecordBatchRequest& request));
};

class FirehoseTests : public testing::Test {
 public:
  void SetUp() override { initAwsSdk(); }
};

TEST_F(FirehoseTests, test_send) {
  FirehoseLogForwarder forwarder;
  auto client = std::make_shared<StrictMock<MockFirehoseClient>>();
  forwarder.client_ = client;

  std::vector<std::string> logs{"{\"foo\":\"bar\"}"};
  Aws::Firehose::Model::PutRecordBatchOutcome outcome;
  outcome.GetResult().SetFailedPutCount(0);
  EXPECT_CALL(*client,
              PutRecordBatch(Property(
                  &Aws::Firehose::Model::PutRecordBatchRequest::GetRecords,
                  ElementsAre(MatchesEntry("{\"foo\":\"bar\",\"log_type\":\"results\"}\n")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(0), forwarder.send(logs, "results"));

  logs = {"{\"bar\":\"foo\"}", "{\"foo\":\"bar\"}"};
  Aws::Firehose::Model::PutRecordBatchResponseEntry entry;
  outcome.GetResult().AddRequestResponses(entry);
  entry.SetErrorCode("foo");
  entry.SetErrorMessage("Foo error");
  outcome.GetResult().SetFailedPutCount(1);
  outcome.GetResult().AddRequestResponses(entry);

  EXPECT_CALL(*client,
              PutRecordBatch(Property(
                  &Aws::Firehose::Model::PutRecordBatchRequest::GetRecords,
                  ElementsAre(MatchesEntry("{\"bar\":\"foo\",\"log_type\":\"results\"}\n"), MatchesEntry("{\"foo\":\"bar\",\"log_type\":\"results\"}\n")))))
      .WillOnce(Return(outcome));
  EXPECT_EQ(Status(1, "Foo error"), forwarder.send(logs, "results"));
}
}
