/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mutex>

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/setrlimit.h>

#include <sys/resource.h>

namespace osquery {

DECLARE_bool(enable_bpf_events);

namespace {
std::once_flag setrlimit_flag;

void configureBPFMemoryLimitsHelper() {
  if (!FLAGS_enable_bpf_events) {
    return;
  }

  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err != 0) {
    throw std::runtime_error(
        "Failed to setup the memory lock limits. The BPF tables may not work "
        "correctly.");
  }
}
} // namespace

Status configureBPFMemoryLimits() {
  try {
    std::call_once(setrlimit_flag, configureBPFMemoryLimitsHelper);
    return Status::success();

  } catch (const std::exception& e) {
    return Status::failure(e.what());
  }
}

} // namespace osquery
