/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/experimental/tracing/syscalls_tracing.h>
#ifdef POSIX
#include <osquery/experimental/tracing/syscalls_tracing_impl.h>
#endif

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

DEFINE_bool(enable_experimental_tracing,
            false,
            "Experimental syscalls tracing");

namespace experimental {
namespace tracing {

void init() {
#ifdef POSIX
  if (FLAGS_enable_experimental_tracing) {
    LOG(INFO) << "Experimental syscall tracing is enabled";
    impl::runService();
  }
#endif
}

} // namespace tracing
} // namespace experimental
} // namespace osquery
