/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD process_open_files: enumerates per-process file descriptors via
 * libprocstat (a base library), the standard FreeBSD equivalent of
 * walking /proc/<pid>/fd/ on Linux.  Only descriptors whose underlying
 * object has a filesystem path are emitted (sockets, pipes, kqueues, etc.
 * have fs_path == NULL and are skipped).
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <libprocstat.h>

#include <set>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

QueryData genOpenFiles(QueryContext& context) {
  QueryData results;

  struct procstat* ps = procstat_open_sysctl();
  if (ps == nullptr) {
    return results;
  }

  unsigned int cnt = 0;
  struct kinfo_proc* procs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &cnt);
  if (procs == nullptr) {
    procstat_close(ps);
    return results;
  }

  // Honour pid predicate (e.g. WHERE pid = 1) when present to avoid the
  // O(processes * fds) blowup.  Use the string-overload of getAll(): the
  // templated getAll<T>(op) silently ignores its `op` argument and would
  // also accept SQLite's LIMIT pushdown (synthetic op
  // SQLITE_INDEX_CONSTRAINT_LIMIT=73) as a pid equality on modern SQLite,
  // turning "SELECT pid FROM process_open_files LIMIT 5" into
  // "WHERE pid = 5".
  std::set<pid_t> wanted;
  bool filter = false;
  if (context.constraints.count("pid") > 0) {
    auto pids = context.constraints.at("pid").getAll(EQUALS);
    if (!pids.empty()) {
      filter = true;
      for (const auto& p : pids) {
        try {
          wanted.insert(static_cast<pid_t>(std::stoll(p)));
        } catch (...) {
          // ignore unparseable pid literals
        }
      }
    }
  }

  for (unsigned int i = 0; i < cnt; i++) {
    pid_t pid = procs[i].ki_pid;
    if (filter && wanted.count(pid) == 0) {
      continue;
    }
    struct filestat_list* head = procstat_getfiles(ps, &procs[i], 0);
    if (head == nullptr) {
      continue;
    }
    struct filestat* fst;
    STAILQ_FOREACH(fst, head, next) {
      if (fst->fs_uflags &
          (PS_FST_UFLAG_TEXT | PS_FST_UFLAG_CDIR | PS_FST_UFLAG_RDIR |
           PS_FST_UFLAG_JAIL | PS_FST_UFLAG_TRACE | PS_FST_UFLAG_MMAP |
           PS_FST_UFLAG_CTTY)) {
        // Skip non-fd entries (cwd, root, mmap regions, …).  Linux's
        // /proc/<pid>/fd/ lists only numbered descriptors, so match that.
        continue;
      }
      if (fst->fs_fd < 0 || fst->fs_path == nullptr ||
          fst->fs_path[0] == '\0') {
        continue;
      }
      Row r;
      r["pid"] = BIGINT(pid);
      r["fd"] = BIGINT(fst->fs_fd);
      r["path"] = fst->fs_path;
      results.push_back(r);
    }
    procstat_freefiles(ps, head);
  }

  procstat_freeprocs(ps, procs);
  procstat_close(ps);
  return results;
}

} // namespace tables
} // namespace osquery
