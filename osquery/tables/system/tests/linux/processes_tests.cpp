/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <osquery/tables/system/linux/processes.h>

namespace osquery {
namespace tables {

namespace {
// Join entries into a nul-delimited block, the way /proc/<pid>/environ is laid
// out.
std::string environBlock(const std::vector<std::string>& entries) {
  std::string content;
  for (const auto& entry : entries) {
    content += entry;
    content.push_back('\0');
  }
  return content;
}
} // namespace

class CGroupTest : public ::testing::Test {};

TEST_F(CGroupTest, systemd_session) {
  auto got =
      parseProcCGroup("0::/user.slice/user-1000.slice/session-6.scope\n");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, no_newline) {
  auto got = parseProcCGroup("0::/user.slice/user-1000.slice/session-6.scope");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, version_1_single_group) {
  auto got = parseProcCGroup(
      "4:cpu,cpuset:/user.slice/user-1000.slice/session-6.scope\n");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, invalid) {
  auto got = parseProcCGroup("0:/user.slice\n");
  EXPECT_EQ("", got);
}

class ProcMapsInodeTest : public ::testing::Test {};

TEST_F(ProcMapsInodeTest, binary_path) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r--p 00000000 08:01 1312 /usr/bin/cat\n"
      "55d0c0a02000-55d0c0a07000 r-xp 00002000 08:01 1312 /usr/bin/cat\n",
      "/usr/bin/cat");
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_with_regex_characters) {
  const std::string path = "/tmp/a+[b]\\h (deleted)";
  auto got = parseProcMapsInode(
      "7f0000000000-7f0000001000 r--p 00000000 08:01 42 /usr/lib/libc.so.6\n"
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312                  " +
          path + "\n",
      path);
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_with_newline) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312 "
      "/tmp/a\\012b (deleted)\n",
      "/tmp/a\nb (deleted)");
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_not_mapped) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312 /tmp/a (deleted)x\n"
      "7ffc0a000000-7ffc0a021000 rw-p 00000000 00:00 0 [stack]\n",
      "/tmp/a (deleted)");
  EXPECT_EQ("", got);
}

class ProcEnvironTest : public ::testing::Test {};

TEST_F(ProcEnvironTest, well_formed) {
  auto got =
      parseProcessEnvironment(environBlock({"PATH=/usr/bin", "HOME=/root"}));
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ("PATH", got[0].first);
  EXPECT_EQ("/usr/bin", got[0].second);
  EXPECT_EQ("HOME", got[1].first);
  EXPECT_EQ("/root", got[1].second);
}

TEST_F(ProcEnvironTest, high_bit_name_does_not_truncate) {
  // An entry whose name begins with a byte that has the high bit set is a
  // negative value where char is signed. The walk must not stop there and
  // drop the entries that follow it.
  auto content = environBlock({"PATH=/usr/bin",
                               std::string(1, static_cast<char>(0xA3)) + "M=x",
                               "LD_PRELOAD=/tmp/x.so"});
  auto got = parseProcessEnvironment(content);
  ASSERT_EQ(3u, got.size());
  EXPECT_EQ("LD_PRELOAD", got[2].first);
  EXPECT_EQ("/tmp/x.so", got[2].second);
}

TEST_F(ProcEnvironTest, no_trailing_nul) {
  // A block with no nul anywhere, as seen from a process that overwrote its
  // own environ region, must be read within bounds and still yield its entry.
  auto got = parseProcessEnvironment(std::string(64, 'A'));
  ASSERT_EQ(1u, got.size());
  EXPECT_EQ(std::string(64, 'A'), got[0].first);
}

} // namespace tables
} // namespace osquery
