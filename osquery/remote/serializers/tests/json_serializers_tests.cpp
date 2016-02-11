/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include "osquery/remote/serializers/json.h"

namespace osquery {

class JSONSerializersTests : public testing::Test {};

TEST_F(JSONSerializersTests, test_serialize) {
  auto json = JSONSerializer();
  boost::property_tree::ptree params;
  params.put<std::string>("foo", "bar");

  std::string serialized;
  auto s = json.serialize(params, serialized);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(serialized, "{\"foo\":\"bar\"}\n");
}

TEST_F(JSONSerializersTests, test_deserialize) {
  auto json = JSONSerializer();
  boost::property_tree::ptree params;
  std::string serialized = "{\"foo\":\"bar\"}\n";
  auto s = json.deserialize(serialized, params);

  boost::property_tree::ptree expected;
  expected.put<std::string>("foo", "bar");

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(params, expected);
}
}
