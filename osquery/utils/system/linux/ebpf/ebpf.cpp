/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/ebpf/ebpf.h>
#include <osquery/utils/versioning/semantic.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <linux/version.h>
#include <sys/utsname.h>

#ifndef __NR_bpf

#if defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__sparc__)
#define __NR_bpf 349
#elif defined(__s390__)
#define __NR_bpf 351
#else
#error __NR_bpf is undefined, probably this arch is not supported.
#endif

#endif // __NR_bpf

namespace osquery {
namespace ebpf {

constexpr int kMinimalLinuxVersionCode = KERNEL_VERSION(4, 9, 0);

Expected<bool, PosixError> isSupportedBySystem() {
  struct utsname utsbuf;
  if (uname(&utsbuf) == -1) {
    return createError(to<PosixError>(errno))
           << "syscall uname() failed: " << boost::io::quoted(strerror(errno));
  }
  auto release_version_exp =
      tryTo<SemanticVersion>(std::string(utsbuf.release));
  if (release_version_exp.isError()) {
    return createError(PosixError::Unknown, release_version_exp.takeError())
           << "uname() release field is malformed"
           << boost::io::quoted(utsbuf.release);
  }
  auto const version = release_version_exp.take();
  return kMinimalLinuxVersionCode <=
         KERNEL_VERSION(version.major, version.minor, version.patches);
}

Expected<int, PosixError> syscall(int cmd, union bpf_attr* attr) {
  int const ret = ::syscall(__NR_bpf, cmd, attr, sizeof(union bpf_attr));
  if (ret < 0) {
    return createError(to<PosixError>(errno))
           << "bpf() syscall failed: " << boost::io::quoted(strerror(errno));
  }
  return ret;
}

} // namespace ebpf
} // namespace osquery
