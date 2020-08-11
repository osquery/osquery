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
#include <sys/queue.h>
#include <libprocstat.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include "osquery/tables/system/freebsd/procstat.h"

namespace osquery {
namespace tables {

void genDescriptors(struct procstat* pstat,
                    struct kinfo_proc* proc,
                    QueryData& results) {

  Row r;
  struct filestat_list* files = nullptr;
  struct filestat* file = nullptr;

  files = procstat_getfiles(pstat, proc, 0);
  if (files == nullptr) {
    return;
  }

  STAILQ_FOREACH(file, files, next) {
    // Skip files that aren't "open" (no fd).
    if (file->fs_fd == -1) {
      continue;
    }

    r["pid"] = INTEGER(proc->ki_pid);
    if (file->fs_path == nullptr) {
      r["path"] = TEXT("");
    } else {
      r["path"] = TEXT(file->fs_path);
    }
    r["fd"] = BIGINT(file->fs_fd);

    results.push_back(r);
  }

  procstat_freefiles(pstat, files);
}

QueryData genOpenFiles(QueryContext& context) {
  QueryData results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);

  for (size_t i = 0; i < cnt; i++) {
    genDescriptors(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);
  return results;
}
}
}
