/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/tables/system/linux/processes.h>

namespace osquery {
namespace tables {

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

} // namespace tables
} // namespace osquery