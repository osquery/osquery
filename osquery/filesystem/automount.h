/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

namespace osquery {

/// A mount point and its filesystem type, as listed in the mount table.
struct MountPoint {
  std::string path;
  std::string type;
};

/**
 * @brief Parses the content of /proc/self/mountinfo, keeping its order.
 *
 * Lines that cannot be parsed are skipped.
 */
std::vector<MountPoint> parseMountInfo(const std::string& content);

/**
 * @brief Tells whether accessing a path would make the automounter mount it.
 *
 * Decided from the mount table alone, without accessing the path. The path is
 * on the mount whose mount point is the longest one that is the path or one of
 * its parents, and of mounts stacked on one mount point, the last one listed
 * is on top. If that mount is an autofs mount, which is also what a systemd
 * automount uses, nothing is mounted at the path yet, and looking up the path
 * or anything under it makes the automounter mount it.
 *
 * @param mounts The mount table, in the order it lists mounts.
 * @param path An absolute path. A relative or empty path is never reported.
 */
bool isUnmountedAutomount(const std::vector<MountPoint>& mounts,
                          const std::string& path);

/**
 * @brief Tells which home directories tables must not read.
 *
 * Tables that read files in every user's home directory would make the
 * automounter mount every automounted home directory that is not mounted yet,
 * which across a fleet mounts all of them on every host at once. A home
 * directory is skipped if it is not mounted yet and reading it would mount it,
 * unless --automount_home_dirs is set. Home directories that are already
 * mounted are read as usual.
 *
 * The mount table is read once, when the filter is created, and only on
 * Linux. Elsewhere no home directory is skipped.
 */
class AutomountHomeFilter {
 public:
  AutomountHomeFilter();

  /// Uses the given mount table instead of the system's, for tests.
  explicit AutomountHomeFilter(std::vector<MountPoint> mounts);

  /// Tells whether the home directory must not be read, logging it if so.
  bool skip(const std::string& home) const;

 private:
  std::vector<MountPoint> mounts_;
};

} // namespace osquery
