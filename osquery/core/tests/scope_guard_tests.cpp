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

TEST_F(ScopeGuardTests, guard_is_called) {
  auto guard_has_been_called = false;
  {
    auto guard = ScopeGuard<>::create(
        [&guard_has_been_called]() { guard_has_been_called = true; });
    ASSERT_FALSE(guard_has_been_called);
  }
  ASSERT_TRUE(guard_has_been_called);
}

TEST_F(ScopeGuardTests, guard_is_called_by_release) {
  auto calls_counter = int{0};
  {
    auto guard = ScopeGuard<>::create([&calls_counter]() { ++calls_counter; });
    EXPECT_EQ(calls_counter, 0);
    guard.release();
    EXPECT_EQ(calls_counter, 1);
  }
  EXPECT_EQ(calls_counter, 2);
}

TEST_F(ScopeGuardTests, example_time_measurement) {
  auto duration = std::chrono::duration<double>{0};
  {
    auto guard = ScopeGuard<>::create(
        [&duration, start = std::chrono::steady_clock::now()]() {
          duration = std::chrono::steady_clock::now() - start;
        });
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
  EXPECT_GE(duration, std::chrono::milliseconds{1});
}

TEST_F(ScopeGuardTests, example_temporary_file) {
  const auto tmp_file_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.core.tests.resource_manager_tests.temporary_file.%%%%.log");
  {
    const auto guard = ScopeGuard<>::create(
        [& file_path = tmp_file_path]() { fs::remove(file_path); });
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
