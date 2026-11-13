/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/core/flags.h>
#include <osquery/filesystem/automount.h>
#include <osquery/filesystem/filesystem.h>

namespace osquery {

DECLARE_bool(automount_home_dirs);

namespace {

/// /home as an autofs indirect map, the way both autofs and a systemd
/// automount set it up, with none of its home directories mounted.
std::vector<MountPoint> homeMap() {
  return {{"/", "xfs"}, {"/proc", "proc"}, {"/home", "autofs"}};
}

} // namespace

class AutomountTests : public testing::Test {
 protected:
  void SetUp() override {
    automount_home_dirs_ = FLAGS_automount_home_dirs;
    FLAGS_automount_home_dirs = false;
  }

  void TearDown() override {
    FLAGS_automount_home_dirs = automount_home_dirs_;
  }

 private:
  bool automount_home_dirs_{false};
};

TEST_F(AutomountTests, test_parse_mountinfo) {
  // Lines as the kernel writes them: with and without optional fields, with
  // an escaped space in the mount point, and one line that is not a mount.
  const std::string mountinfo =
      "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/root rw\n"
      "45 22 0:40 / /home rw,relatime shared:25 - autofs systemd-1 rw,fd=50\n"
      "61 45 0:52 / /home/alice rw shared:31 master:7 - nfs4 srv:/alice rw\n"
      "70 22 0:60 / /mnt/my\\040homes rw - autofs /etc/auto.homes rw\n"
      "not a mountinfo line\n";

  auto mounts = parseMountInfo(mountinfo);
  ASSERT_EQ(mounts.size(), 4U);
  EXPECT_EQ(mounts[0].path, "/");
  EXPECT_EQ(mounts[0].type, "xfs");
  EXPECT_EQ(mounts[1].path, "/home");
  EXPECT_EQ(mounts[1].type, "autofs");
  EXPECT_EQ(mounts[2].path, "/home/alice");
  EXPECT_EQ(mounts[2].type, "nfs4");
  EXPECT_EQ(mounts[3].path, "/mnt/my homes");
  EXPECT_EQ(mounts[3].type, "autofs");
}

#ifdef __linux__
TEST_F(AutomountTests, test_parse_system_mountinfo) {
  std::string content;
  ASSERT_TRUE(readFile("/proc/self/mountinfo", content).ok());

  auto mounts = parseMountInfo(content);
  EXPECT_TRUE(std::any_of(mounts.begin(), mounts.end(), [](const auto& m) {
    return m.path == "/";
  }));
}
#endif

TEST_F(AutomountTests, test_indirect_map_home_not_mounted) {
  auto mounts = homeMap();
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/alice"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/alice/.config/autostart"));
}

TEST_F(AutomountTests, test_indirect_map_home_mounted) {
  auto mounts = homeMap();
  mounts.push_back({"/home/alice", "nfs4"});

  EXPECT_FALSE(isUnmountedAutomount(mounts, "/home/alice"));
  EXPECT_FALSE(isUnmountedAutomount(mounts, "/home/alice/.bash_history"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/bob"));
}

TEST_F(AutomountTests, test_direct_map) {
  // A direct map puts an autofs mount on each mount point, and mounts the
  // filesystem on top of it.
  std::vector<MountPoint> mounts = {{"/", "xfs"}, {"/data/alice", "autofs"}};
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/data/alice"));
  EXPECT_FALSE(isUnmountedAutomount(mounts, "/data"));

  mounts.push_back({"/data/alice", "nfs"});
  EXPECT_FALSE(isUnmountedAutomount(mounts, "/data/alice"));
}

TEST_F(AutomountTests, test_systemd_automount_mounted) {
  // x-systemd.automount on /home, after the real filesystem was mounted on it.
  std::vector<MountPoint> mounts = {
      {"/", "xfs"}, {"/home", "autofs"}, {"/home", "xfs"}};
  EXPECT_FALSE(isUnmountedAutomount(mounts, "/home/alice"));
}

TEST_F(AutomountTests, test_nested_automount) {
  std::vector<MountPoint> mounts = {
      {"/", "xfs"}, {"/home", "ext4"}, {"/home/projects", "autofs"}};
  EXPECT_FALSE(isUnmountedAutomount(mounts, "/home/alice"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/projects/alice"));
}

TEST_F(AutomountTests, test_no_automount) {
  EXPECT_FALSE(isUnmountedAutomount({{"/", "xfs"}}, "/home/alice"));
  EXPECT_FALSE(isUnmountedAutomount({}, "/home/alice"));
}

TEST_F(AutomountTests, test_path_normalization) {
  auto mounts = homeMap();
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/alice/"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home//alice"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/home/./alice"));
  EXPECT_TRUE(isUnmountedAutomount(mounts, "/srv/../home/alice"));
}

TEST_F(AutomountTests, test_mount_point_boundary) {
  EXPECT_FALSE(isUnmountedAutomount(homeMap(), "/homework/alice"));
}

TEST_F(AutomountTests, test_relative_or_empty_path) {
  auto mounts = homeMap();
  EXPECT_FALSE(isUnmountedAutomount(mounts, "home/alice"));
  EXPECT_FALSE(isUnmountedAutomount(mounts, ""));
}

TEST_F(AutomountTests, test_home_filter) {
  auto mounts = homeMap();
  mounts.push_back({"/home/alice", "nfs4"});
  AutomountHomeFilter automount_filter(mounts);

  EXPECT_FALSE(automount_filter.skip("/home/alice"));
  EXPECT_TRUE(automount_filter.skip("/home/bob"));
  EXPECT_FALSE(automount_filter.skip("/root"));

  // The flag makes every home directory readable again.
  FLAGS_automount_home_dirs = true;
  EXPECT_FALSE(automount_filter.skip("/home/bob"));
}

} // namespace osquery
