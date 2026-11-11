/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>
#include <string>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void readKernelPanic(const std::string& panicLogFilePath, QueryData& results);

class KernelPanicsTests : public testing::Test {
 protected:
  void SetUp() override {
    directory_ = fs::temp_directory_path() /
                 fs::unique_path("osquery.kernel_panics_tests.%%%%-%%%%");
    ASSERT_TRUE(fs::create_directories(directory_));
  }

  void TearDown() override {
    fs::remove_all(directory_);
  }

  /// Parse a panic log in the pre-JSON format used by macOS 10.14 and earlier.
  Row parsePanicLog(const std::string& content) {
    auto panic_file = directory_ / fs::path("test.panic");

    {
      auto fout = std::ofstream(panic_file.native());
      fout << content;
    }

    QueryData results;
    readKernelPanic(panic_file.string(), results);

    EXPECT_EQ(results.size(), 1U);
    return results.empty() ? Row{} : results[0];
  }

  fs::path directory_;
};

TEST_F(KernelPanicsTests, test_process_name_with_no_value) {
  // A key with no value leaves a single token behind, so there is no value
  // token to report.
  auto r = parsePanicLog(
      "Process name corresponding to current thread\n"
      "System model name: MacBookPro18,3\n");
  EXPECT_EQ(r.count("name"), 0U);

  r = parsePanicLog(
      "Process name corresponding to current thread:\n"
      "System model name: MacBookPro18,3\n");
  EXPECT_EQ(r.count("name"), 0U);
}

TEST_F(KernelPanicsTests, test_process_name_is_reported) {
  auto r = parsePanicLog(
      "Process name corresponding to current thread: kernel_task\n"
      "System model name: MacBookPro18,3\n");
  EXPECT_EQ(r["name"], "kernel_task");

  // The same key on the last line of the log.
  r = parsePanicLog(
      "System model name: MacBookPro18,3\n"
      "Process name corresponding to current thread: launchd\n");
  EXPECT_EQ(r["name"], "launchd");
}

} // namespace tables
} // namespace osquery
