/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef WIN32
#include <pwd.h>
#endif

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

class PermissionsTests : public testing::Test {
 public:
  PermissionsTests() : perm_path_(kTestWorkingDirectory + "lowperms/") {}

  void SetUp() { fs::create_directories(perm_path_); }

  void TearDown() { fs::remove_all(perm_path_); }

 protected:
  std::string perm_path_;
};

#ifndef WIN32
TEST_F(PermissionsTests, test_explicit_drop) {
  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo(getuid(), getgid()));
    // We can attempt to drop to the previously-dropped privilege.
    EXPECT_TRUE(dropper->dropTo(getuid(), getgid()));
  }

  {
    auto dropper = DropPrivileges::get();
    // Make sure that an out-of-scope dropper "restore"
    EXPECT_FALSE(dropper->dropped_);

    uid_t expected_user = 0U;
    EXPECT_EQ(dropper->to_user_, expected_user);

    gid_t expected_group = 0U;
    EXPECT_EQ(dropper->to_group_, expected_group);

    // Checking if we are generally in a deprivileged mode.
    auto dropper2 = DropPrivileges::get();
    EXPECT_FALSE(dropper2->dropped());
  }
}

TEST_F(PermissionsTests, test_path_drop) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (path) deprivilege testing";
    return;
  }

  // Attempt to drop to nobody based on ownership of paths.
  auto nobody = getpwnam("nobody");
  ASSERT_NE(nobody, nullptr);

  {
    int status = chown(perm_path_.c_str(), nobody->pw_uid, nobody->pw_gid);
    ASSERT_EQ(status, 0);

    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropToParent(perm_path_ + "ro"));
    EXPECT_TRUE(dropper->dropped_);
    EXPECT_EQ(dropper->to_user_, nobody->pw_uid);

    // Even though this is possible and may make sense, it is confusing!
    EXPECT_FALSE(dropper->dropTo(getuid(), getgid()));

    // Make sure the dropper worked!
    EXPECT_EQ(geteuid(), nobody->pw_uid);
  }

  // Now that the dropper is gone, the effective user/group should be restored.
  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}

TEST_F(PermissionsTests, test_nobody_drop) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (explicit) deprivilege testing";
    return;
  }

  // Attempt to drop to nobody.
  auto nobody = getpwnam("nobody");
  ASSERT_NE(nobody, nullptr);

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo(nobody->pw_uid, nobody->pw_gid));
    EXPECT_EQ(geteuid(), nobody->pw_uid);
  }

  // Now that the dropper is gone, the effective user/group should be restored.
  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}
#endif
}
