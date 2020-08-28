/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/optional.hpp>

#include <gtest/gtest.h>

#include "osquery/utils/debug/debug_only.h"

namespace osquery {

namespace {

class TestEmptyClass {};

} // namespace

GTEST_TEST(DebugOnly, fail) {
#ifndef NDEBUG
  ASSERT_DEATH(debug_only::fail("This code should fail"),
               "debug.*This code should fail");
#endif
}

GTEST_TEST(DebugOnly, verify) {
#ifndef NDEBUG
  ASSERT_DEATH(
      debug_only::verify([]() { return false; },
                         "This code should fail because lambda return false"),
      "debug.*This code should fail because lambda return false");
#endif
}

GTEST_TEST(DebugOnly, verifyTrue) {
  debug_only::verifyTrue(true, "This code must not fail");
#ifndef NDEBUG
  ASSERT_DEATH(debug_only::verifyTrue(false, "This code should fail"),
               "debug.*This code should fail");
#endif
}

GTEST_TEST(DebugOnly, verify_do_nothing_in_non_debug_mode) {
#ifdef NDEBUG
  // This code will be compiled and run only in release mode according to macro
  // conditions around. That means code inside lambda is not going to be run.
  // Let's check it here.
  debug_only::verify(
      []() {
        EXPECT_TRUE(false);
        return false;
      },
      "This check should not fail");
#endif
}

GTEST_TEST(DebugOnlyVar, size) {
#ifndef NDEBUG
  ASSERT_EQ(sizeof(long long), sizeof(debug_only::Var<long long>));
#else
  ASSERT_EQ(sizeof(TestEmptyClass), sizeof(debug_only::Var<long long>));
#endif
}

GTEST_TEST(DebugOnlyVar, verify) {
  auto var = debug_only::Var<int>{0};
  var.verify([](auto v) { return v == 0; }, "This should be fine");
  var.verifyEqual(0, "This also should be fine");
#ifndef NDEBUG
  ASSERT_DEATH(var.verify([](auto v) { return v == 9; },
                          "There is some funny joke supposed to be here"),
               "debug.*There is some funny joke supposed to be here");
  ASSERT_DEATH(var.verifyEqual(12, "One more hilarious joke, have a fun"),
               "debug.*One more hilarious joke, have a fun");
  ASSERT_DEATH(var.verify("And one more, don't worry this is the last one"),
               "debug.*And one more, don't worry this is the last one");
#endif
}

GTEST_TEST(DebugOnlyVar, implicit_constructor) {
  // object can be created from underlying value
  debug_only::Var<int> dbg_var = 12;
  dbg_var.verifyEqual(12, "This check should not fail");
}

GTEST_TEST(DebugOnlyVar, set) {
  auto var = debug_only::Var<int>{12};
  var.verify(
      [](auto value) {
        EXPECT_EQ(12, value);
        return true;
      },
      "This check should not fail");
  var.set(291);
  var.verify(
      [](auto value) {
        EXPECT_EQ(291, value);
        return true;
      },
      "This check should not fail");
}

GTEST_TEST(DebugOnlyVar, update) {
  auto var = debug_only::Var<int>{12};
  var.verify(
      [](auto value) {
        EXPECT_EQ(12, value);
        return true;
      },
      "This check should not fail");
  // where
  var.update([](auto old) { return old + 17; });
  // let's verify update was successful
  var.verify(
      [](auto value) {
        EXPECT_EQ(12 + 17, value);
        return true;
      },
      "This check should not fail");
}

GTEST_TEST(DebugOnlyVar, verify_in_non_debug_mode_should_not_be_run) {
  auto var = debug_only::Var<int>{12};
  var.verify(
      [](auto value) {
        EXPECT_EQ(12, value);
        return true;
      },
      "This check should not fail");
#ifdef NDEBUG
  // This code will be compiled and run only in release mode according to macro
  // conditions around. That means code inside lambda is not going to be run.
  // Let's check it here.
  var.verify(
      [](auto value) {
        boost::ignore_unused(value);
        EXPECT_TRUE(false);
        return false;
      },
      "This check should not fail");
#endif
}

struct Gun {
  explicit Gun(int bullets) : bullets_(bullets) {}

  void shot() {
    dbg.update([this](auto v) { return bullets_ == 0 ? v + 1 : v; });
    --bullets_;
  }

  int bullets_;
  debug_only::Var<int> dbg = 0;
};

GTEST_TEST(DebugOnlyVar, example_debug_check_watchdog) {
  auto gun = Gun(2);
  gun.shot();
  gun.shot();
  gun.dbg.verify([](auto v) { return v == 0; },
                 "There is not supposed to have a failure, just an example");
}

GTEST_TEST(DebugOnlyVar, example_debug_check_return_value) {
  auto test_function = [](int i) { return std::to_string(i); };
  debug_only::Var<std::string> dbg = test_function(11);
  dbg.verify([](const auto& str) { return !str.empty(); },
             "The return value is not supposed to be empty string. But for "
             "performance reasons let's check it only in debug mode.");
}

} // namespace osquery
