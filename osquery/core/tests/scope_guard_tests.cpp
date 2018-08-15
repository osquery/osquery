/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <gtest/gtest.h>

#include <boost/core/ignore_unused.hpp>
#include <boost/filesystem.hpp>

#include <osquery/logger.h>
#include <osquery/tests/test_util.h>

#include "osquery/core/scope_guard.h"

namespace fs = boost::filesystem;

namespace osquery {

class ScopeGuardTests : public testing::Test {};

TEST_F(ScopeGuardTests, value_access) {
  auto text = std::string{"Nothing changes because the guard make a copy"};
  {
    auto guard = scope_guard::value(
        text, [](const auto& resource) { boost::ignore_unused(resource); });
    EXPECT_EQ(*guard, text);
    guard->assign("the new thing");
    EXPECT_EQ(*guard, "the new thing");
  }
  EXPECT_EQ(text, "Nothing changes because the guard make a copy");
}

TEST_F(ScopeGuardTests, value_with_ref_access) {
  auto text = std::string{
      "It is going to be changed because of std::reference_wrapper"};
  {
    auto guard = scope_guard::value(std::ref(text), [](const auto& resource) {
      boost::ignore_unused(resource);
    });
    EXPECT_EQ(guard->get(), text);
    guard->get().assign("It has been changed");
    EXPECT_EQ(guard->get(), "It has been changed");
  }
  EXPECT_EQ(text, "It has been changed");
}

TEST_F(ScopeGuardTests, cref_access) {
  auto const text = std::string{
      "It is going to be changed because of std::reference_wrapper"};
  {
    auto guard =
        scope_guard::cref(text, [text_copy = text](const auto& resource) {
          EXPECT_EQ(resource, text_copy);
        });
    EXPECT_EQ(guard->get(), text);
  }
}

TEST_F(ScopeGuardTests, demolisher_is_called) {
  auto demolisher_has_been_called = false;
  {
    auto guard = scope_guard::value(
        34978, [&demolisher_has_been_called](const auto& resource) {
          demolisher_has_been_called = true;
        });
    ASSERT_EQ(*guard, 34978);
  }
  EXPECT_TRUE(demolisher_has_been_called);
}

TEST_F(ScopeGuardTests, atExit_is_called) {
  auto demolisher_has_been_called = false;
  {
    auto guard = scope_guard::atExit(
        [&demolisher_has_been_called]() {
          demolisher_has_been_called = true;
        });
    ASSERT_FALSE(demolisher_has_been_called);
  }
  ASSERT_TRUE(demolisher_has_been_called);
}

namespace {

class DeletionCounter final {
 public:
  explicit DeletionCounter() {
    ++counter;
  }
  DeletionCounter(const DeletionCounter&) {
    ++counter;
  }
  DeletionCounter(DeletionCounter&&) {
    ++counter;
  }
  DeletionCounter& operator=(const DeletionCounter&) {
    ++counter;
    return *this;
  }
  DeletionCounter& operator=(DeletionCounter&&) {
    ++counter;
    return *this;
  }
  ~DeletionCounter() {
    --counter;
  }

  static int counter;
};

int DeletionCounter::counter = 0;

} // namespace

TEST_F(ScopeGuardTests, deletion) {
  // Substitution of deleter in std::unique_ptr can cause memory leaks.
  // Let's check it doesn't happen.
  {
    DeletionCounter::counter = 0;
    auto guard =
        scope_guard::value(DeletionCounter{}, [](const auto& resource) {
          boost::ignore_unused(resource);
          EXPECT_EQ(DeletionCounter::counter, 1);
        });
    EXPECT_EQ(DeletionCounter::counter, 1);
  }
  EXPECT_EQ(DeletionCounter::counter, 0);
}

namespace {

class MoveOnlyTestClass {
 public:
  explicit MoveOnlyTestClass(std::string text) : msg(std::move(text)) {}
  MoveOnlyTestClass(const MoveOnlyTestClass&) = delete;
  MoveOnlyTestClass(MoveOnlyTestClass&&) = default;
  MoveOnlyTestClass& operator=(const MoveOnlyTestClass&) = delete;
  MoveOnlyTestClass& operator=(MoveOnlyTestClass&&) = default;

  std::string msg;
};

} // namespace

TEST_F(ScopeGuardTests, value_with_move_only_object) {
  const auto guard = scope_guard::value(
      MoveOnlyTestClass{"Resource acquisition is initialization"},
      [](const auto& resource) { boost::ignore_unused(resource); });
  EXPECT_EQ(guard->msg, "Resource acquisition is initialization");
}

TEST_F(ScopeGuardTests, example_time_measurement) {
  auto duration = std::chrono::duration<double>{0};
  {
    auto guard = scope_guard::atExit(
        [&duration, start=std::chrono::steady_clock::now()]() {
          duration = std::chrono::steady_clock::now() - start;
        });
    std::this_thread::sleep_for(std::chrono::microseconds{2});
  }
  EXPECT_GE(duration, std::chrono::microseconds{2});
}

TEST_F(ScopeGuardTests, example_temporary_file) {
  const auto tmp_file_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.core.tests.resource_manager_tests.temporary_file.%%%%.log");
  {
    const auto guard = scope_guard::atExit(
      [&file_path=tmp_file_path]() {
        if (fs::exists(file_path)) {
          fs::remove(file_path);
        }
      }
    );
    { // create file
      auto fout = std::ofstream(tmp_file_path.native(),
                                std::ios::out | std::ios::binary);
      fout << "write some text to temporary file";
    }
    ASSERT_TRUE(fs::exists(tmp_file_path)); // let's check file exists
  }
  // context is closed, file should be removed
  ASSERT_FALSE(fs::exists(tmp_file_path));
}

} // namespace osquery
