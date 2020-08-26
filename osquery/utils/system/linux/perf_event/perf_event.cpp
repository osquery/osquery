/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/perf_event/perf_event.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <unistd.h>

#ifndef __NR_perf_event_open
#if defined(__PPC__)
#define __NR_perf_event_open 319
#elif defined(__i386__)
#define __NR_perf_event_open 336
#elif defined(__x86_64__)
#define __NR_perf_event_open 298
#elif defined(__aarch64__)
#define __NR_perf_event_open 364
#else
#error __NR_perf_event_open must be defined
#endif
#endif

namespace osquery {
namespace perf_event_open {

Expected<int, PosixError> syscall(struct perf_event_attr* attr,
                                  pid_t const pid,
                                  int const cpu,
                                  int const group_fd,
                                  unsigned long const flags) {
  auto ret = ::syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
  if (ret < 0) {
    return createError(to<PosixError>(errno))
           << "syscall perf_event_open failed "
           << boost::io::quoted(strerror(errno));
  }
  return ret;
}

} // namespace perf_event_open
} // namespace osquery
