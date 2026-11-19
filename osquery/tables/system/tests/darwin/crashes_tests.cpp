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

#include <osquery/core/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void readCrashDumpJSON(const std::string& crashLogFilePath, Row& r);

class CrashesTests : public testing::Test {
 protected:
  void SetUp() override {
    directory_ = fs::temp_directory_path() /
                 fs::unique_path("osquery.crashes_tests.%%%%-%%%%");
    ASSERT_TRUE(fs::create_directories(directory_));
  }

  void TearDown() override {
    fs::remove_all(directory_);
  }

  /// Parse a diagnostic report in the JSON format used since macOS 12.
  Row parseCrashDump(const std::string& content) {
    auto ips_file = directory_ / fs::path("test.ips");

    {
      auto fout = std::ofstream(ips_file.native());
      fout << content;
    }

    Row r;
    readCrashDumpJSON(ips_file.string(), r);
    EXPECT_EQ(r["crash_path"], ips_file.string());
    return r;
  }

  fs::path directory_;
};

TEST_F(CrashesTests, test_json_crash_dump_is_parsed) {
  auto r = parseCrashDump(
      R"({"app_name":"Example","bug_type":"309"})"
      "\n"
      R"({"pid":1234,"procPath":"/Applications/Example.app/Contents/MacOS/Example",)"
      R"("exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"}})");
  EXPECT_EQ(r["pid"], "1234");
  EXPECT_EQ(r["path"], "/Applications/Example.app/Contents/MacOS/Example");
  EXPECT_EQ(r["exception_type"], "EXC_BAD_ACCESS (SIGSEGV)");
}

TEST_F(CrashesTests, test_deeply_nested_json_is_refused) {
  // A valid header followed by content nested deeply enough to overflow the
  // stack of a recursive JSON parser
  const std::size_t depth = 1000000;
  auto r =
      parseCrashDump("{}" + std::string(depth, '[') + std::string(depth, ']'));
  EXPECT_EQ(r.count("pid"), 0U);
}

} // namespace tables
} // namespace osquery
