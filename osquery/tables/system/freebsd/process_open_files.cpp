/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <stdlib.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/queue.h>
#include <libprocstat.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/tables/system/freebsd/procstat.h"

#define DECLARE_TABLE_IMPLEMENTATION_process_open_files
#include <generated/tables/tbl_process_open_files_defs.hpp>

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
