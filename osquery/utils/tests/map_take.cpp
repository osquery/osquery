/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_map>

#include <gtest/gtest.h>

#include <osquery/utils/map_take.h>

namespace osquery {

namespace {

template <typename MapType>
void testTryTake() {
  auto m = MapType{
      {"dev", "/dev/"},
      {"etc", "/etc/"},
      {"usr", "/usr/"},
      {"bin", "/bin/"},
      {"var", "/var/"},
  };
  ASSERT_EQ(m.size(), 5);
  {
    auto exp = tryTake(m, "dev");
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(exp.get(), "/dev/");
  }
  ASSERT_EQ(m.size(), 4);
  {
    auto exp = tryTake(m, "etc");
    ASSERT_FALSE(exp.isError());
    EXPECT_EQ(exp.get(), "/etc/");
  }
  ASSERT_EQ(m.size(), 3);
  {
    auto exp = tryTake(m, "no such key");
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getErrorCode(), MapTakeError::NoSuchKey);
  }
  EXPECT_EQ(m.size(), 3);
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
void testTryTakeCopy() {
  auto m = MapType{
      {"dev", "/dev/"},
      {"etc", "/etc/"},
      {"usr", "/usr/"},
      {"bin", "/bin/"},
      {"var", "/var/"},
  };
  ASSERT_EQ(m.size(), 5);
  {
    auto const exp = tryTakeCopy(m, "dev");
    ASSERT_TRUE(exp.isValue());
    EXPECT_EQ(exp.get(), "/dev/");
  }
  ASSERT_EQ(m.size(), 5);
  {
    auto const exp = tryTakeCopy(m, "no such key");
    ASSERT_TRUE(exp.isError());
    EXPECT_EQ(exp.getErrorCode(), MapTakeError::NoSuchKey);
  }
  EXPECT_EQ(m.size(), 5);
}

} // namespace

GTEST_TEST(GetTests, tryTakeCopy_on_map) {
  testTryTakeCopy<std::map<std::string, std::string>>();
}

GTEST_TEST(GetTests, tryTakeCopy_on_unordered_map) {
  testTryTakeCopy<std::unordered_map<std::string, std::string>>();
}

} // namespace osquery
