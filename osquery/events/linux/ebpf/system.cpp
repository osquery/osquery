/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/system.h"

#include <osquery/core/conversions.h>
#include <osquery/debug/debug_only.h>

#include <sys/utsname.h>

#include <cstring>

namespace osquery {
namespace ebpf {

namespace impl {

using boost::io::quoted;

KernelReleaseVersion getKernelReleaseVersion() {
  auto version = KernelReleaseVersion{};
  struct utsname utsbuf;
  if (uname(&utsbuf) == -1) {
    LOG(WARNING) << "syscall uname() failed: " << quoted(strerror(errno));
    debug_only::fail("syscall uname() failed");
    return version;
  }
  auto release = std::string(utsbuf.release);
  auto const major_number_pos = release.find('.');
  if (major_number_pos == std::string::npos) {
    LOG(WARNING) << "Wrong major version field: " << quoted(utsbuf.release);
    debug_only::fail("Wrong major version field");
    return version;
  }
  version.major = tryTo<int>(release.substr(0, major_number_pos)).takeOr(0);

  auto const minor_number_pos = release.find('.', major_number_pos + 1);
  if (minor_number_pos == std::string::npos) {
    LOG(WARNING) << "Wrong minor version field: " << quoted(utsbuf.release);
    debug_only::fail("Wrong release minor version field");
    return version;
  }
  version.minor =
      tryTo<int>(release.substr(major_number_pos + 1,
                                minor_number_pos - major_number_pos))
          .takeOr(0);

  auto const patch_number_pos = release.find('-', minor_number_pos + 1);
  if (patch_number_pos == std::string::npos) {
    LOG(WARNING) << "Wrong patches field: " << quoted(utsbuf.release);
    debug_only::fail("Wrong release patches field");
    return version;
  }
  version.patches =
      tryTo<int>(release.substr(minor_number_pos + 1,
                                patch_number_pos - minor_number_pos))
          .takeOr(0);
  return version;
}

} // namespace impl

} // namespace ebpf
} // namespace osquery
