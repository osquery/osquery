/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <sstream>
#include <utility>

#include <osquery/core/flags.h>
#include <osquery/filesystem/automount.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace osquery {

FLAG(bool,
     automount_home_dirs,
     false,
     "Read home directories that are not mounted yet, which makes the "
     "automounter mount them");

namespace {

bool isOctalDigit(char c, char max = '7') {
  return c >= '0' && c <= max;
}

/// Decodes the \ooo escapes the kernel writes for space, tab, newline and
/// backslash in mount points.
std::string unescapeMountPoint(const std::string& path) {
  std::string unescaped;
  unescaped.reserve(path.size());
  for (size_t i = 0; i < path.size(); ++i) {
    if (path[i] == '\\' && i + 3 < path.size() &&
        isOctalDigit(path[i + 1], '3') && isOctalDigit(path[i + 2]) &&
        isOctalDigit(path[i + 3])) {
      unescaped +=
          static_cast<char>((path[i + 1] - '0') * 64 + (path[i + 2] - '0') * 8 +
                            (path[i + 3] - '0'));
      i += 3;
    } else {
      unescaped += path[i];
    }
  }
  return unescaped;
}

/// Removes ".", "..", repeated separators and a trailing separator from an
/// absolute path, without accessing the filesystem.
std::string normalizeAbsolutePath(const std::string& path) {
  std::vector<std::string> components;
  size_t start = 0;
  while (start <= path.size()) {
    auto end = path.find('/', start);
    if (end == std::string::npos) {
      end = path.size();
    }

    auto component = path.substr(start, end - start);
    if (component == "..") {
      if (!components.empty()) {
        components.pop_back();
      }
    } else if (!component.empty() && component != ".") {
      components.push_back(std::move(component));
    }
    start = end + 1;
  }

  std::string normalized;
  for (const auto& component : components) {
    normalized += "/" + component;
  }
  return normalized.empty() ? "/" : normalized;
}

/// Tells whether path is mount_point or under it. Both must be normalized.
bool isAtOrUnder(const std::string& mount_point, const std::string& path) {
  if (mount_point == "/" || path == mount_point) {
    return true;
  }
  return path.size() > mount_point.size() &&
         path.compare(0, mount_point.size(), mount_point) == 0 &&
         path[mount_point.size()] == '/';
}

} // namespace

std::vector<MountPoint> parseMountInfo(const std::string& content) {
  std::vector<MountPoint> mounts;
  std::istringstream lines(content);
  std::string line;
  while (std::getline(lines, line)) {
    // Each line is: mount ID, parent ID, major:minor, root, mount point,
    // mount options, zero or more optional fields, "-", filesystem type,
    // source and superblock options.
    std::istringstream line_fields(line);
    std::vector<std::string> fields;
    std::string field;
    while (line_fields >> field) {
      fields.push_back(std::move(field));
    }
    if (fields.size() < 7) {
      continue;
    }

    auto separator = std::find(fields.begin() + 6, fields.end(), "-");
    if (separator == fields.end() || separator + 1 == fields.end()) {
      continue;
    }

    auto mount_point = unescapeMountPoint(fields[4]);
    if (mount_point.empty() || mount_point[0] != '/') {
      continue;
    }
    mounts.push_back({std::move(mount_point), *(separator + 1)});
  }
  return mounts;
}

bool isUnmountedAutomount(const std::vector<MountPoint>& mounts,
                          const std::string& path) {
  if (path.empty() || path[0] != '/') {
    return false;
  }

  auto target = normalizeAbsolutePath(path);
  const MountPoint* containing = nullptr;
  size_t containing_length = 0;
  for (const auto& mount : mounts) {
    auto mount_point = normalizeAbsolutePath(mount.path);
    // Of mounts stacked on one mount point, the last one listed is on top, so
    // a later mount on an equally long mount point replaces an earlier one.
    if (isAtOrUnder(mount_point, target) &&
        mount_point.size() >= containing_length) {
      containing = &mount;
      containing_length = mount_point.size();
    }
  }

  return containing != nullptr && containing->type == "autofs";
}

AutomountHomeFilter::AutomountHomeFilter() {
#ifdef __linux__
  if (FLAGS_automount_home_dirs) {
    return;
  }

  // If the mount table cannot be read, no home directory is skipped, as
  // before this filter existed.
  std::string content;
  if (readFile("/proc/self/mountinfo", content, false).ok()) {
    mounts_ = parseMountInfo(content);
  } else {
    VLOG(1) << "Cannot read the mount table, home directories that are not "
               "mounted yet may be automounted";
  }
#endif
}

AutomountHomeFilter::AutomountHomeFilter(std::vector<MountPoint> mounts)
    : mounts_(std::move(mounts)) {}

bool AutomountHomeFilter::skip(const std::string& home) const {
  if (FLAGS_automount_home_dirs || !isUnmountedAutomount(mounts_, home)) {
    return false;
  }

  VLOG(1) << "Skipping home directory " << home
          << " which is not mounted: reading it would make the automounter "
             "mount it";
  return true;
}

} // namespace osquery
