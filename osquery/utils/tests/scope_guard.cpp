/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <boost/core/ignore_unused.hpp>
#include <boost/filesystem.hpp>

#include <osquery/utils/scope_guard.h>

namespace fs = boost::filesystem;

namespace osquery {

class ScopeGuardTests : public testing::Test {};

TEST_F(ScopeGuardTests, guard_is_called) {
  auto guard_has_been_called = false;
  {
    auto guard = scope_guard::create(
        [&guard_has_been_called]() { guard_has_been_called = true; });
    ASSERT_FALSE(guard_has_been_called);
  }
  ASSERT_TRUE(guard_has_been_called);
}

TEST_F(ScopeGuardTests, example_time_measurement) {
  auto duration = std::chrono::duration<double>{0};
  {
    auto guard = scope_guard::create(
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
  { // create file
    auto fout =
        std::ofstream(tmp_file_path.native(), std::ios::out | std::ios::binary);
    fout << "write some text to temporary file";
  }
  {
    const auto guard = scope_guard::create(
        [& file_path = tmp_file_path]() { fs::remove(file_path); });
    ASSERT_TRUE(fs::exists(tmp_file_path)); // let's check file exists
  }
  // context is closed, file should be removed
  ASSERT_FALSE(fs::exists(tmp_file_path));
}

} // namespace osquery
