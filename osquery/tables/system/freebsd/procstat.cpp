/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <stdlib.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/queue.h>

#include <libprocstat.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

unsigned int getProcesses(QueryContext& context,
                          struct procstat** pstat,
                          struct kinfo_proc** procs) {
  std::set<std::string> pids;

  *pstat = procstat_open_sysctl();
  if (*pstat == nullptr) {
    TLOG << "Problem in procstat_open_sysctl()";
    return 0;
  }

  unsigned int cnt = 0;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);

    // Generate data for all pids in the vector.
    // If there are comparison constraints this could apply the operator
    // before generating the process structure.
    for (const auto& pid : pids) {
      *procs = procstat_getprocs(*pstat, KERN_PROC_PID, std::stoi(pid), &cnt);
      if (*procs == nullptr) {
        TLOG << "Problem retrieving processes";
        procstat_close(*pstat);
        *pstat = nullptr;
        return 0;
      }
    }
  } else {
    // Get all PIDS.
    *procs = procstat_getprocs(*pstat, KERN_PROC_PROC, 0, &cnt);
    if (*procs == nullptr) {
      TLOG << "Problem retrieving processes";
      procstat_close(*pstat);
      *pstat = nullptr;
      return 0;
    }
  }

  return cnt;
}

void procstatCleanup(struct procstat* pstat, struct kinfo_proc* procs) {
  if (procs != nullptr) {
    procstat_freeprocs(pstat, procs);
  }

  if (pstat != nullptr) {
    procstat_close(pstat);
  }
}
}
}
