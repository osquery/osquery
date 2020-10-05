/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <poll.h>
#include <pwd.h>

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

class PermissionsTests : public testing::Test {
 public:
  PermissionsTests()
      : perm_path_(fs::temp_directory_path() /
                   fs::unique_path("lowperms.%%%%.%%%%")) {}

  void SetUp() override {
    fs::create_directories(perm_path_);
  }

  void TearDown() override {
    fs::remove_all(perm_path_);
  }

 protected:
  fs::path perm_path_;
};

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

    // Checking if we are generally in an unprivileged mode.
    auto dropper2 = DropPrivileges::get();
    EXPECT_FALSE(dropper2->dropped());
  }
}

TEST_F(PermissionsTests, test_path_drop) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (path) unprivileged testing";
    return;
  }

  // Attempt to drop to nobody based on ownership of paths.
  auto nobody = getpwnam("nobody");
  ASSERT_NE(nobody, nullptr);

  {
    int status =
        chown(perm_path_.string().c_str(), nobody->pw_uid, nobody->pw_gid);
    ASSERT_EQ(status, 0);

    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropToParent((perm_path_ / "ro").string()));
    EXPECT_TRUE(dropper->dropped_);
    EXPECT_EQ(dropper->to_user_, nobody->pw_uid);

    // Dropping "up" to root should fail.
    // Even though this is possible and may make sense, it is confusing!
    EXPECT_FALSE(dropper->dropTo(0, 0));

    // Make sure the dropper worked!
    EXPECT_EQ(geteuid(), nobody->pw_uid);
  }

  // Now that the dropper is gone, the effective user/group should be restored.
  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}

TEST_F(PermissionsTests, test_functional_drop) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (explicit) unprivileged testing";
    return;
  }

  auto file_path = kTestWorkingDirectory + "permissions-file2";

  {
    writeTextFile(file_path, "data");
    ASSERT_TRUE(platformChmod(file_path, 0400));
  }

  {
    auto nobody = getpwnam("nobody");
    auto dropper = DropPrivileges::get();
    dropper->dropTo(nobody->pw_uid, nobody->pw_gid);
    PlatformFile fd(file_path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_FALSE(fd.isValid());
  }

  osquery::removePath(file_path);
}

TEST_F(PermissionsTests, test_nobody_drop) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping (explicit) unprivileged testing";
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

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo(std::to_string(nobody->pw_uid),
                                std::to_string(nobody->pw_gid)));
    EXPECT_EQ(geteuid(), nobody->pw_uid);
  }

  // Now that the dropper is gone, the effective user/group should be restored.
  EXPECT_EQ(geteuid(), getuid());
  EXPECT_EQ(getegid(), getgid());
}

std::string kMultiThreadPermissionPath;

class PermissionsRunnable : public InternalRunnable {
 public:
  PermissionsRunnable() : InternalRunnable("PermissionsRunnable") {}
  PermissionsRunnable(const std::string& name) : InternalRunnable(name) {}

 private:
  virtual void start() override {
    while (!interrupted()) {
      if (!writeTextFile(kMultiThreadPermissionPath, "test")) {
        throw std::runtime_error("Cannot write " + kMultiThreadPermissionPath);
      }
      ticks++;
    }
  }

 public:
  std::atomic<size_t> ticks{0};
};

class PermissionsPollRunnable : public PermissionsRunnable {
 public:
  PermissionsPollRunnable() : PermissionsRunnable("PermissionsPollRunnable") {}

 private:
  void start() override {
    PlatformFile file(kMultiThreadPermissionPath,
                      PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
    auto file_fd = file.nativeHandle();

    struct pollfd fds[1];
    while (!interrupted()) {
      std::memset(fds, 0, sizeof(fds));
      fds[0].fd = file_fd;

      result = poll(fds, 1, 1);
      if (result == 0) {
        ticks++;
      }
    }
  }

 public:
  std::atomic<int> result;
};

bool waitForTick(const std::shared_ptr<PermissionsRunnable>& runnable) {
  size_t now = runnable->ticks;
  size_t timeout = 1000;
  size_t delay = 0;
  while (delay < timeout) {
    sleepFor(20);
    if (runnable->ticks > now) {
      return true;
    }
    sleepFor(200);
    delay += 220;
  }
  return false;
}

TEST_F(PermissionsTests, test_multi_thread_permissions) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping multi-thread deprivilege testing";
    return;
  }

  ASSERT_EQ(0U, geteuid());

  // Set the multi-thread path, which both threads will write into.
  auto multi_thread_path = perm_path_ / "threadperms.txt";
  kMultiThreadPermissionPath = multi_thread_path.string();

  // This thread has super-user permissions.
  ASSERT_TRUE(writeTextFile(kMultiThreadPermissionPath, "test", 600));

  // Start our permissions thread.
  auto perms_thread = std::make_shared<PermissionsRunnable>();
  Dispatcher::addService(perms_thread);

  // Wait for the permissions thread to write once.
  EXPECT_TRUE(waitForTick(perms_thread));

  // Attempt to drop to nobody.
  auto nobody = getpwnam("nobody");
  EXPECT_NE(nobody, nullptr);

  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo(nobody->pw_uid, nobody->pw_gid));
    EXPECT_EQ(geteuid(), nobody->pw_uid);

    // Now we wait for the permissions thread to write once while this thread's
    // permissions are dropped.
    EXPECT_TRUE(waitForTick(perms_thread));
  }

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}

TEST_F(PermissionsTests, test_multi_thread_poll) {
  if (getuid() != 0) {
    LOG(WARNING) << "Not root, skipping multi-thread deprivilege testing";
    return;
  }

  ASSERT_EQ(0U, geteuid());

  // Set the multi-thread path, which both threads will write into.
  auto multi_thread_path = perm_path_ / "threadperms.txt";
  kMultiThreadPermissionPath = multi_thread_path.string();

  // Start our permissions thread.
  auto pool_thread = std::make_shared<PermissionsPollRunnable>();
  Dispatcher::addService(pool_thread);

  // Wait for the permissions thread to write once.
  EXPECT_TRUE(waitForTick(pool_thread));

  auto nobody = getpwnam("nobody");
  EXPECT_NE(nobody, nullptr);
  {
    auto dropper = DropPrivileges::get();
    EXPECT_TRUE(dropper->dropTo(nobody->pw_uid, nobody->pw_gid));
    EXPECT_EQ(geteuid(), nobody->pw_uid);

    EXPECT_TRUE(waitForTick(pool_thread));
  }

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}
}
