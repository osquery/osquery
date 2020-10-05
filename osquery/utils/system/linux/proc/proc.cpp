/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/proc/proc.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>

#include <fcntl.h>
#include <sys/syscall.h>

namespace osquery {
namespace proc {

namespace fs = boost::filesystem;

const std::string kProc = "/proc";
const std::string kMountNamespace = "/ns/mnt";

namespace {

inline fs::path attrPath(const std::string& pid, char const* attr) {
  auto attr_path = fs::path(kProc);
  attr_path /= pid;
  attr_path /= attr;
  return attr_path;
}

inline fs::path attrPath(pid_t pid, char const* attr) {
  return attrPath(std::to_string(pid), attr);
}

} // namespace

std::string cmdline(pid_t const pid) {
  auto attr_path = attrPath(pid, "cmdline");
  auto ifs = std::ifstream(attr_path.c_str(),
                           std::ios_base::in | std::ios_base::binary);
  using iter = std::istreambuf_iterator<std::string::value_type>;
  auto content = std::string{iter(ifs), iter{}};

  // According to kernel docs the command-line arguments appear in this string
  // as a set of strings separated by null bytes ('\0'), with a further null
  // byte after the last string. Let's get rid of them.
  std::replace(content.begin(), content.end(), '\0', ' ');
  boost::algorithm::trim_right(content);
  return content;
}

static std::string makeNSPath(const char* pid_or_path) {
  std::string nspath = pid_or_path;
  if (nspath.empty()) {
    return nspath;
  }
  if (nspath[0] == '/') {
    return nspath;
  }
  nspath = kProc + "/";
  nspath += pid_or_path;
  nspath += kMountNamespace;
  return nspath;
}

/*
 * Use SYS_setns syscall to set namespace.
 * NOTE: setns() function not added until glibc 2.14
 */
Status setLinuxNamespace(const char* cpath, std::string& feedback) {
  static int origfd = 0;
  static std::string lastns;
  std::string nspath = makeNSPath(cpath);

  // need to keep handle to original namespace

  if (origfd <= 0) {
    std::string original_mnt_path =
        kProc + "/" + std::to_string(getpid()) + kMountNamespace;

    origfd = open(original_mnt_path.c_str(), O_RDONLY);
    if (origfd <= 0) {
      feedback +=
          "Unable to open original namespace descriptor: " + original_mnt_path +
          "\n";
    }
  }

  // if in a namespace, restore original

  if (!lastns.empty()) {
    lastns.clear();

    // restore original namespace

    int result = static_cast<int>(syscall(SYS_setns, origfd, 0));

    if (result == -1) {
      return Status::failure("ERROR: Unable to restore original namespace");
    }
  }

  if (nspath.empty()) {
    feedback += "Back in original namespace\n";
    return Status::success();
  }

  // switch to container namespace

  int fd = open(nspath.c_str(), O_RDONLY);
  if (fd <= 0) {
    return Status::failure("Unable to open namespace descriptor: " + nspath);
  }

  int result = static_cast<int>(syscall(SYS_setns, fd, 0));
  close(fd);

  if (result == -1) {
    return Status::failure("Unable to switch to namespace");
  }

  lastns = nspath;

  feedback += "Now in namespace:" + nspath + "\n";
  return Status::success();
}

} // namespace proc
} // namespace osquery
