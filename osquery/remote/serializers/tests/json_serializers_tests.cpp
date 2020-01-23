/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include "osquery/remote/serializers/json.h"

namespace osquery {

class JSONSerializersTests : public testing::Test {};

TEST_F(JSONSerializersTests, test_serialize) {
  auto json = JSONSerializer();
  JSON params;
  params.add("foo", "bar");

  std::string serialized;
  auto s = json.serialize(params, serialized);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(serialized, "{\"foo\":\"bar\"}");
}

TEST_F(JSONSerializersTests, test_deserialize) {
  auto json = JSONSerializer();
  JSON params;
  std::string serialized = "{\"foo\":\"bar\"}";
  auto s = json.deserialize(serialized, params);

  JSON expected;
  expected.add("foo", "bar");

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(params.doc(), expected.doc());
}
}
