/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef WIN32
/// Suppress a C4244 warning in gtest-printers.h (double -> BiggestInt
/// conversion)
#pragma warning(push, 3)
#pragma warning(disable : 4244)
#endif

#include <gtest/gtest.h>

#ifdef WIN32
#pragma warning(pop)
#endif

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/info/platform_type.h>

#include "osquery/core/flagalias.h"

namespace osquery {

DECLARE_string(test_string_flag);

class FlagsTests : public testing::Test {
 public:
  FlagsTests() {}

  void SetUp() {}
};

FLAG(string, test_string_flag, "TEST STRING", "TEST DESCRIPTION");

TEST_F(FlagsTests, test_set_get) {
  // Test the core gflags functionality.
  EXPECT_EQ(FLAGS_test_string_flag, "TEST STRING");

  // Check that the gflags flag name was recorded in the osquery flag tracker.
  auto all_flags = Flag::flags();
  EXPECT_EQ(all_flags.count("test_string_flag"), 1U);

  // Update the value of the flag, and access through the osquery wrapper.
  FLAGS_test_string_flag = "NEW TEST STRING";
  EXPECT_EQ(Flag::getValue("test_string_flag"), "NEW TEST STRING");
}

TEST_F(FlagsTests, test_defaults) {
  // Make sure the flag value was not reset.
  EXPECT_EQ(FLAGS_test_string_flag, "NEW TEST STRING");

  // Now test that the default value is tracked.
  EXPECT_FALSE(Flag::isDefault("test_string_flag"));

  // Check the default value accessor.
  std::string default_value;
  auto status = Flag::getDefaultValue("test_mistake", default_value);
  EXPECT_FALSE(status.ok());
  status = Flag::getDefaultValue("test_string_flag", default_value);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(default_value, "TEST STRING");
}

TEST_F(FlagsTests, test_details) {
  // Make sure flag details are tracked correctly.
  auto all_flags = Flag::flags();
  auto flag_info = all_flags["test_string_flag"];

  EXPECT_EQ(flag_info.type, "string");
  EXPECT_EQ(flag_info.description, "TEST DESCRIPTION");
  EXPECT_EQ(flag_info.default_value, "TEST STRING");
  EXPECT_EQ(flag_info.value, "NEW TEST STRING");
  EXPECT_EQ(flag_info.detail.shell, false);
  EXPECT_EQ(flag_info.detail.external, false);
}

SHELL_FLAG(bool, shell_only, true, "TEST SHELL DESCRIPTION");
EXTENSION_FLAG(bool, extension_only, true, "TEST EXTENSION DESCRIPTION");

TEST_F(FlagsTests, test_flag_detail_types) {
  EXPECT_TRUE(FLAGS_shell_only);
  EXPECT_TRUE(FLAGS_extension_only);

  auto all_flags = Flag::flags();
  EXPECT_TRUE(all_flags["shell_only"].detail.shell);
  EXPECT_TRUE(all_flags["extension_only"].detail.external);
}

FLAG_ALIAS(bool, shell_only_alias, shell_only);

TEST_F(FlagsTests, test_aliases) {
  EXPECT_TRUE(FLAGS_shell_only_alias);
  FLAGS_shell_only = false;
  EXPECT_FALSE(FLAGS_shell_only);
  EXPECT_FALSE(FLAGS_shell_only_alias);
}

FLAG(int32, test_int32, 1, "none");
FLAG_ALIAS(google::int32, test_int32_alias, test_int32);

FLAG(int64, test_int64, (int64_t)1 << 34, "none");
FLAG_ALIAS(google::int64, test_int64_alias, test_int64);

FLAG(double, test_double, 4.2, "none");
FLAG_ALIAS(double, test_double_alias, test_double);

FLAG(string, test_string, "test", "none");
FLAG_ALIAS(std::string, test_string_alias, test_string);

TEST_F(FlagsTests, test_alias_types) {
  // Test int32 lexical casting both ways.
  EXPECT_EQ(FLAGS_test_int32_alias, 1);
  FLAGS_test_int32_alias = 2;
  EXPECT_EQ(FLAGS_test_int32, 2);
  FLAGS_test_int32 = 3;
  EXPECT_EQ(FLAGS_test_int32_alias, 3);
  EXPECT_TRUE(FLAGS_test_int32_alias > 0);

  EXPECT_EQ(FLAGS_test_int64_alias, (int64_t)1 << 34);
  FLAGS_test_int64_alias = (int64_t)1 << 35;
  EXPECT_EQ(FLAGS_test_int64, (int64_t)1 << 35);
  FLAGS_test_int64 = (int64_t)1 << 36;
  EXPECT_EQ(FLAGS_test_int64_alias, (int64_t)1 << 36);
  EXPECT_TRUE(FLAGS_test_int64_alias > 0);

  EXPECT_EQ(FLAGS_test_double_alias, 4.2);
  FLAGS_test_double_alias = 2.4;
  EXPECT_EQ(FLAGS_test_double, 2.4);
  FLAGS_test_double = 22.44;
  EXPECT_EQ(FLAGS_test_double_alias, 22.44);
  EXPECT_TRUE(FLAGS_test_double_alias > 0);

  // Compile-time type checking will not compare typename T to const char*
  std::string value = FLAGS_test_string_alias;
  EXPECT_EQ(value, "test");
  FLAGS_test_string_alias = "test2";
  EXPECT_EQ(FLAGS_test_string, "test2");
  FLAGS_test_string = "test3";

  // Test both the copy and assignment constructor aliases.
  value = FLAGS_test_string_alias;
  auto value2 = (std::string)FLAGS_test_string_alias;
  EXPECT_EQ(value, "test3");
}

TEST_F(FlagsTests, test_platform) {
  PlatformType mPlatformType = PlatformType::TYPE_POSIX;
  EXPECT_TRUE(isPlatform(PlatformType::TYPE_POSIX, mPlatformType));

  mPlatformType = PlatformType::TYPE_OSX | PlatformType::TYPE_POSIX;
  EXPECT_TRUE(isPlatform(PlatformType::TYPE_POSIX, mPlatformType));
  EXPECT_TRUE(isPlatform(PlatformType::TYPE_OSX, mPlatformType));

  // Now set and check a valid casting.
  mPlatformType = static_cast<PlatformType>(8);
  EXPECT_EQ(PlatformType::TYPE_LINUX, mPlatformType);

  // Set something that doesn't make sense
  mPlatformType = PlatformType::TYPE_WINDOWS | PlatformType::TYPE_BSD;
  EXPECT_FALSE(isPlatform(PlatformType::TYPE_LINUX, mPlatformType));
  EXPECT_FALSE(isPlatform(PlatformType::TYPE_OSX, mPlatformType));
}
}
