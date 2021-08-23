/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/socket_events.h>

#include <asm/unistd.h>

namespace osquery {

FLAG(bool,
     audit_allow_accept_socket_events,
     true,
     "Include rows for accept socket events");

namespace {

const std::set<int> kBaseSyscallSet = {__NR_bind, __NR_connect};

}

std::set<int> getSocketEventsSyscalls() {
  auto syscall_set = kBaseSyscallSet;

  if (FLAGS_audit_allow_accept_socket_events) {
    syscall_set.insert(__NR_accept);
    syscall_set.insert(__NR_accept4);
  }

  return syscall_set;
}

} // namespace osquery
