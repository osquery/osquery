/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "memory.h"

#include <chrono>
#include <malloc.h>

#include <osquery/core/flags.h>
#include <osquery/core/watcher.h>
#include <osquery/filesystem/linux/proc.h>
#include <osquery/logger/logger.h>

namespace osquery {
DECLARE_bool(disable_watchdog);

#ifdef OSQUERY_LINUX

void releaseRetainedMemory() {
  /* The logic used for choosing the limit at which malloc_trim is called is as
     follows: Verify if the flag has been set by the user or not
        1. If it's then
          a. If the value is 0, trimming is disabled, return
          b. If not, use that value
        2. If it's not, then verify if the watchdog is active or not
          a. If it's, then the limit is 80% of the watchdog memory limit
          b. If it's not, then the limit is 200MB

     Any error in getting the flag information or converting the value into an
     integer, will make the value fall back to 200MB. */

  gflags::CommandLineFlagInfo flag_info;
  auto flag_found =
      gflags::GetCommandLineFlagInfo("malloc_trim_threshold", &flag_info);

  std::uint32_t current_threshold = 200;

  // This shouldn't happen, but we attempt to recover
  if (!flag_found) {
    LOG(ERROR) << "No flag malloc_trim_threshold found! Using default of 200MB";
  } else if (flag_info.is_default) {
    if (!FLAGS_disable_watchdog) {
      auto watchdog_limit = getWorkerLimit(WatchdogLimitType::MEMORY_LIMIT);
      current_threshold = (watchdog_limit * 80) / 100;
    }
  } else {
    auto current_flag_threshold_res =
        tryTo<std::uint32_t>(flag_info.current_value);

    // This shouldn't happen too, but we attempt to recover
    if (current_flag_threshold_res.isError()) {
      LOG(ERROR) << "Error converting malloc_trim_threshold value to integer. "
                    "Using default of 200MB";
    } else {
      current_threshold = current_flag_threshold_res.take();

      // malloc trim has been disabled
      if (current_threshold == 0) {
        return;
      }
    }
  }

  auto used_memory_res = getProcRSS("self");

  if (used_memory_res.isError()) {
    VLOG(1) << "Failed to get retained memory: "
            << used_memory_res.takeError().getMessage();
    return;
  }

  auto used_memory = used_memory_res.take() / (1000 * 1000);

  if (used_memory > current_threshold) {
    VLOG(1) << "The amount of retained memory is approaching the "
               "threshold, attempting to release memory";
    malloc_trim(0);
  }
}
#endif

} // namespace osquery
