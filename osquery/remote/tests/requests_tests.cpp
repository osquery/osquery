/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/serializers/json.h"

namespace osquery {

class RequestsTests : public testing::Test {
 public:
  void SetUp() {}
};

class MockTransport : public Transport {
 public:
  Status sendRequest() {
    response_status_ = Status(0, "OK");
    return response_status_;
  }

  Status sendRequest(const std::string& params) {
    response_params_.put<std::string>("foo", "baz");
    response_status_ = Status(0, "OK");
    return response_status_;
  }
};

class MockSerializer : public Serializer {
 public:
  std::string getContentType() const { return "mock"; }

  Status serialize(const boost::property_tree::ptree& params,
                   std::string& serialized) {
    return Status(0, "OK");
  }

  Status deserialize(const std::string& serialized,
                     boost::property_tree::ptree& params) {
    return Status(0, "OK");
  }
};

TEST_F(RequestsTests, test_call) {
  auto req = Request<MockTransport, MockSerializer>("foobar");
  auto s1 = req.call();
  EXPECT_TRUE(s1.ok());

  boost::property_tree::ptree params;
  auto s2 = req.getResponse(params);
  EXPECT_TRUE(s2.ok());
  boost::property_tree::ptree empty_ptree;
  EXPECT_EQ(params, empty_ptree);
}

TEST_F(RequestsTests, test_call_with_params) {
  auto req = Request<MockTransport, MockSerializer>("foobar");
  boost::property_tree::ptree params;
  params.put<std::string>("foo", "bar");
  auto s1 = req.call(params);
  EXPECT_TRUE(s1.ok());

  boost::property_tree::ptree recv;
  auto s2 = req.getResponse(recv);
  EXPECT_TRUE(s2.ok());

  boost::property_tree::ptree expected;
  expected.put<std::string>("foo", "baz");
  EXPECT_EQ(recv, expected);
}
}
