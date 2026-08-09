/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class AIAssistantChatsUtilsTest : public ::testing::Test {};

TEST_F(AIAssistantChatsUtilsTest, test_iso8601_to_unix_time) {
  EXPECT_EQ(iso8601ToUnixTime("1970-01-01T00:00:00Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T07:59:23.977Z"), 1777795163);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T07:59:23"), 1777795163);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03 07:59:23Z"), 1777795163);

  // A leap day, and the day after it, in a year divisible by 4.
  EXPECT_EQ(iso8601ToUnixTime("2024-02-29T00:00:00Z"), 1709164800);
  EXPECT_EQ(iso8601ToUnixTime("2024-03-01T00:00:00Z"), 1709251200);

  // 2000 is a leap year, 1900 was not; the day after February in both
  // has to land in the right place.
  EXPECT_EQ(iso8601ToUnixTime("2000-03-01T00:00:00Z"), 951868800);
  EXPECT_EQ(iso8601ToUnixTime("1900-03-01T00:00:00Z"), -2203891200);

  // Anything that is not a timestamp reads as "none recorded".
  EXPECT_EQ(iso8601ToUnixTime(""), 0);
  EXPECT_EQ(iso8601ToUnixTime("yesterday"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-13-03T07:59:23Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T25:59:23Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("20260503T075923Z"), 0);
}

TEST_F(AIAssistantChatsUtilsTest, test_read_json_lines) {
  // The production path splits entries out of a file as it streams in,
  // so the case worth covering is an entry that straddles the boundary
  // between two reads.
  auto path = boost::filesystem::temp_directory_path() /
              boost::filesystem::unique_path("osquery-jsonl-%%%%.jsonl");

  const std::string filler(4096, 'x');
  const std::size_t kEntries = 100;
  {
    std::ofstream out(path.string(), std::ios::binary);
    for (std::size_t i = 0; i < kEntries; ++i) {
      out << "{\"n\":" << i << ",\"pad\":\"" << filler << "\"}\n";
    }
    // A file does not have to end with a newline, and the last entry is
    // still an entry.
    out << "{\"n\":last}";
  }

  std::vector<std::string> entries;
  auto status = readJsonLines(path.string(), [&](const std::string& line) {
    if (!line.empty()) {
      entries.push_back(line);
    }
  });
  boost::filesystem::remove(path);

  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(entries.size(), kEntries + 1);
  EXPECT_EQ(entries.front().substr(0, 8), "{\"n\":0,\"");
  EXPECT_EQ(entries[kEntries - 1].substr(0, 8), "{\"n\":99,");
  EXPECT_EQ(entries.back(), "{\"n\":last}");
  for (const auto& entry : entries) {
    EXPECT_EQ(entry.find('\n'), std::string::npos);
  }
}

} // namespace tables
} // namespace osquery
