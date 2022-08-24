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

} // namespace tables
} // namespace osquery