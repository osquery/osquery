/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "proc.h"

namespace osquery {
std::optional<std::vector<pid_t>> procProcesses() {
  int bufsize = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
  if (bufsize <= 0) {
    return std::nullopt;
  }

  // Use twice the number of PIDs returned to handle races.
  std::vector<pid_t> pids(2 * bufsize);

  bufsize = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), 2 * bufsize);
  if (bufsize <= 0) {
    return std::nullopt;
  }

  std::vector<pid_t> cleaned_pid_list;
  auto num_pids = bufsize / sizeof(pid_t);
  cleaned_pid_list.reserve(num_pids);

  for (std::size_t i = 0; i < num_pids; ++i) {
    auto pid = pids[i];

    if (pid == 0 || pid < 0) {
      continue;
    }

    cleaned_pid_list.emplace_back(pid);
  }

  return cleaned_pid_list;
}
} // namespace osquery
