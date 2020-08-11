/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/syscalls_tracing.h>
#ifdef LINUX
#include <osquery/experimental/tracing/syscalls_tracing_impl.h>
#endif

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>

namespace osquery {

DEFINE_bool(enable_experimental_tracing,
            false,
            "Experimental syscalls tracing");

namespace events {

void init_syscall_tracing() {
#ifdef LINUX
  if (FLAGS_enable_experimental_tracing) {
    LOG(INFO) << "Experimental syscall tracing is enabled";
    impl::runSyscallTracingService();
  }
#endif
}

} // namespace events
} // namespace osquery
