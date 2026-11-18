/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <pwd.h>
#include <unistd.h>

#include <string>

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/registry/registry_interface.h>

namespace osquery {

// Dropping to a user by name queries the `users` table, so these tests live
// with the system tables rather than with the other DropPrivileges tests.
class DropPrivilegesTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(DropPrivilegesTests, test_unknown_user_drop) {
  const std::string unknown_user{"osquery-unknown-user"};
  ASSERT_EQ(getpwnam(unknown_user.c_str()), nullptr);

  {
    auto dropper = DropPrivileges::get();
    EXPECT_FALSE(dropper->dropTo(unknown_user));

    // The IDs are used instead, and the current IDs never need a drop.
    EXPECT_TRUE(dropper->dropToUserOrIds(unknown_user, getuid(), getgid()));
  }

  if (getuid() != 0) {
    // Only root can drop to other IDs, so the fallback fails too.
    auto dropper = DropPrivileges::get();
    EXPECT_FALSE(
        dropper->dropToUserOrIds(unknown_user, getuid() + 1, getgid() + 1));
    EXPECT_FALSE(dropper->dropped());
    return;
  }

  // Root can drop to any IDs, they do not need to belong to an account.
  const uid_t fallback_uid{65534};
  const gid_t fallback_gid{65534};

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(
        dropper->dropToUserOrIds(unknown_user, fallback_uid, fallback_gid));
    EXPECT_TRUE(dropper->dropped_);
    EXPECT_EQ(geteuid(), fallback_uid);
    EXPECT_EQ(getegid(), fallback_gid);
  }

  // Now that the dropper is gone, the effective user/group should be restored.
  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}

TEST_F(DropPrivilegesTests, test_nobody_or_overflow_drop) {
  if (getuid() != 0) {
    GTEST_SKIP() << "Not root, skipping the drop to nobody";
  }

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropToNobodyOrOverflow());
    EXPECT_TRUE(dropper->dropped());
    EXPECT_NE(geteuid(), 0U);
    EXPECT_NE(getegid(), 0U);
  }

  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}

} // namespace osquery
