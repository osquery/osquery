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

#include <osquery/core/utils.h>

#include "osquery/core/conversions.h"

#include "osquery/tests/test_util.h"

namespace osquery {

class TestValue {
  public:
    explicit TestValue() = default;
    explicit TestValue(
        std::string str
    )
      : text(std::move(str))
    {
    }

    TestValue(const TestValue&) = delete;
    TestValue(TestValue&&) = default;

    TestValue& operator=(const TestValue&) = delete;
    TestValue& operator=(TestValue&&) = default;

  public:
    std::string text;
};

GTEST_TEST(CoreUtilsTests, tryGetCopy) {
  const auto m = std::unordered_map<std::string, std::string>{
    {"key", "value"},
  };
  {
    auto exp = tryGetCopy(m, "key");
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(exp.get(), "value");
  }
  {
    auto exp = tryGetCopy(m, "absent key");
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getErrorCode(), GetError::KeyError);
  }
}

GTEST_TEST(CoreUtilsTests, tryTake) {
  auto m = std::unordered_map<std::string, std::string>{
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

// GTEST_TEST(CoreUtilsTests, tryGet) {
//   const auto m = std::unordered_map<std::string, std::string>{
//     {"key", "value"},
//   };
//   auto exp = tryGet(m, "key");
//   ASSERT_FALSE(exp.isError());
//   ASSERT_EQ(exp.get(), "value");
//   auto expDefault = tryGet(m, "absent key");
//   ASSERT_TRUE(expDefault.isError());
//   ASSERT_EQ(expDefault.get_or(std::string{"value"}), "value");
// }
// GTEST_TEST(CoreUtilsTests, tryGet_) {
//   auto m = std::unordered_map<std::string, TestValue>{};
//   m.emplace("key", TestValue{"value"});
//   auto exp = tryGet(m, "key");
//   ASSERT_FALSE(exp.isError());
//   ASSERT_EQ(exp.get().get().text, "value");
// }
GTEST_TEST(CoreUtilsTests, getOr) {
  auto m = std::unordered_map<std::string, std::string>{
    {"key", "value"},
    {"kKey", "vValue"},
  };
  {
    auto exp = getOr(m, "key", "default");
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(exp.get(), "value");
  }
}

}
