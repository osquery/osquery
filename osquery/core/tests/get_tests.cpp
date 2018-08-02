/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include <unordered_map>

#include <gtest/gtest.h>

#include <osquery/core/get.h>

#include "osquery/tests/test_util.h"

namespace osquery {

namespace {

template <typename MapType>
void testTryTake() {
  auto m = MapType{
      {"key", "value"},
      {"kKey", "vValue"},
  };
  ASSERT_EQ(m.size(), 2);
  {
    auto exp = tryTake(m, "key");
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(exp.get(), "value");
  }
  ASSERT_EQ(m.size(), 1);
  {
    auto exp = tryTake(m, "absent key");
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getErrorCode(), GetError::KeyError);
  }
  ASSERT_EQ(m.size(), 1);
}

} // namespace

GTEST_TEST(GetTests, tryTake_on_map) {
  testTryTake<std::map<std::string, std::string>>();
}
GTEST_TEST(GetTests, tryTake_on_unordered_map) {
  testTryTake<std::unordered_map<std::string, std::string>>();
}

namespace {

template <typename MapType>
void testTakeOr() {
  auto m = MapType{
      {"key", "value"},
      {"kKey", "vValue"},
  };
  ASSERT_EQ(m.size(), 2);
  {
    auto const exp = tryTakeCopy(m, "key");
    ASSERT_TRUE(exp.isValue());
    EXPECT_EQ(exp.get(), "value");
  }
  {
    auto const exp = tryTakeCopy(m, "no such key");
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getErrorCode(), GetError::KeyError);
  }
}

} // namespace

GTEST_TEST(GetTests, tryTakeCopy_on_map) {
  testTakeOr<std::map<std::string, std::string>>();
}

GTEST_TEST(GetTests, tryTakeCopy_on_unordered_map) {
  testTakeOr<std::unordered_map<std::string, std::string>>();
}

namespace {

class TestValue {
 public:
  explicit TestValue(std::string str) : text(std::move(str)) {}

  TestValue(const TestValue&) = delete;
  TestValue(TestValue&&) = delete;

  TestValue& operator=(const TestValue&) = delete;
  TestValue& operator=(TestValue&&) = delete;

 public:
  std::string text;
};

template <typename MapType>
void testGetOr() {
  auto m = MapType{};
  m.emplace("key", "value");
  const auto& cm = m;
  TestValue const defaultValue{"default value"};
  {
    auto const& exp = getOr(cm, "key", defaultValue);
    ASSERT_EQ(exp.text, "value");
  }
  {
    auto const& exp2 = getOr(cm, "no such key", defaultValue);
    ASSERT_EQ(exp2.text, "default value");
  }
}

} // namespace

GTEST_TEST(GetTests, getOr_non_copyable_object_in_map) {
  testGetOr<std::map<std::string, TestValue>>();
}

GTEST_TEST(GetTests, getOr_non_copyable_object_in_unordered_map) {
  testGetOr<std::unordered_map<std::string, TestValue>>();
}

} // namespace osquery
