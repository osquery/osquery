/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/experimental/tracing/syscalls_tracing.h>
#ifdef LINUX
#include <osquery/experimental/tracing/syscalls_tracing_impl.h>
#endif

#include <osquery/flags.h>
#include <osquery/logger.h>

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
