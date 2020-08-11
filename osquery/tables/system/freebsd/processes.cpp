/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <paths.h>

/// Required defines for libprocstat.
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/user.h>

#include <libprocstat.h>

#include "osquery/tables/system/freebsd/procstat.h"
#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/sql/dynamic_table_row.h>

namespace osquery {
namespace tables {

void genProcessEnvironment(struct procstat* pstat,
                           struct kinfo_proc* proc,
                           QueryData& results) {
  char** envs = procstat_getenvv(pstat, proc, 0);
  if (envs == nullptr) {
    return;
  }

  for (unsigned int i = 0; envs[i] != nullptr; i++) {
    Row r;
    r["pid"] = INTEGER(proc->ki_pid);

    auto buf = std::string(envs[i]);
    auto idx = buf.find_first_of("=");
    if (idx != std::string::npos) {
      r["key"] = buf.substr(0, idx);
      r["value"] = buf.substr(idx + 1);
    }
    results.push_back(r);
  }

  procstat_freeenvv(pstat);
}

void genProcessMap(struct procstat* pstat,
                   struct kinfo_proc* proc,
                   QueryData& results) {
  unsigned int cnt = 0;
  struct kinfo_vmentry* vmentry = procstat_getvmmap(pstat, proc, &cnt);
  if (vmentry == nullptr) {
    return;
  }

  for (unsigned int i = 0; i < cnt; i++) {
    Row r;

    r["pid"] = INTEGER(proc->ki_pid);
    r["path"] = vmentry[i].kve_path;
    r["device"] = INTEGER(vmentry[i].kve_vn_rdev);
    r["inode"] = INTEGER(vmentry[i].kve_vn_fileid);
    r["offset"] = INTEGER(vmentry[i].kve_offset);

    // To match the linux implementation, convert to hex.
    char addr_str[17] = {0};
    sprintf(addr_str, "%016lx", vmentry[i].kve_start);
    r["start"] = "0x" + std::string(addr_str);
    sprintf(addr_str, "%016lx", vmentry[i].kve_end);
    r["end"] = "0x" + std::string(addr_str);

    std::string permissions;
    permissions += (vmentry[i].kve_protection & KVME_PROT_READ) ? 'r' : '-';
    permissions += (vmentry[i].kve_protection & KVME_PROT_WRITE) ? 'w' : '-';
    permissions += (vmentry[i].kve_protection & KVME_PROT_EXEC) ? 'x' : '-';
    // COW is stored as a flag on FreeBSD, but osquery lumps it in the
    // permissions column.
    permissions += (vmentry[i].kve_flags & KVME_FLAG_COW) ? 'p' : '-';
    r["permissions"] = std::move(permissions);

    if (vmentry[i].kve_vn_fileid == 0 && !r["path"].empty()) {
      r["pseudo"] = INTEGER("1");
    } else {
      r["pseudo"] = INTEGER("0");
    }

    results.push_back(r);
  }

  procstat_freevmmap(pstat, vmentry);
}

void genProcess(struct procstat* pstat,
                struct kinfo_proc* proc,
                TableRows& results) {
  auto r = make_table_row();
  r["pid"] = INTEGER(proc->ki_pid);
  r["parent"] = INTEGER(proc->ki_ppid);
  r["name"] = proc->ki_comm;
  r["uid"] = INTEGER(proc->ki_ruid);
  r["euid"] = INTEGER(proc->ki_uid);
  r["gid"] = INTEGER(proc->ki_rgid);
  r["egid"] = INTEGER(proc->ki_groups[0]);

  static char path[PATH_MAX] = {0};
  if (procstat_getpathname(pstat, proc, path, sizeof(path)) == 0) {
    r["path"] = path;
    // If the path of the executable that started the process is available and
    // the path exists on disk, set on_disk to 1. If the path is not
    // available, set on_disk to -1. If, and only if, the path of the
    // executable is available and the file does NOT exist on disk, set on_disk
    // to 0.
    r["on_disk"] = osquery::pathExists(r["path"]).toString();
  }

  char** args = procstat_getargv(pstat, proc, 0);
  if (args != nullptr) {
    for (unsigned int i = 0; args[i] != nullptr; i++) {
      r["cmdline"] += args[i];
      // Need to add spaces between arguments, except last one.
      if (args[i + 1] != nullptr) {
        r["cmdline"] += ' ';
      }
    }

    procstat_freeargv(pstat);
  }

  struct filestat_list* files = procstat_getfiles(pstat, proc, 0);
  if (files != nullptr) {
    struct filestat* file = nullptr;
    STAILQ_FOREACH(file, files, next) {
      if (file->fs_path == nullptr) {
        continue;
      }

      if (file->fs_uflags & PS_FST_UFLAG_CDIR) {
        r["cwd"] = file->fs_path;
      } else if (file->fs_uflags & PS_FST_UFLAG_RDIR) {
        r["root"] = file->fs_path;
      }
    }

    procstat_freefiles(pstat, files);
  }

  unsigned int cnt = 0;
  struct kinfo_vmentry* vmentry = procstat_getvmmap(pstat, proc, &cnt);
  if (vmentry != nullptr) {
    // Add up all the resident pages for each vmmap entry.
    size_t pages = 0;
    for (unsigned int i = 0; i < cnt; i++) {
      pages += vmentry[i].kve_resident;
    }

    // The column is in bytes.
    r["resident_size"] += INTEGER(pages * getpagesize());

    procstat_freevmmap(pstat, vmentry);
  }

  // XXX: Not sure how to get these on FreeBSD yet.
  r["wired_size"] = INTEGER("0");
  r["phys_footprint"] = INTEGER("0");

  r["system_time"] = INTEGER(proc->ki_rusage.ru_stime.tv_sec);
  r["user_time"] = INTEGER(proc->ki_rusage.ru_utime.tv_sec);
  r["start_time"] = INTEGER(proc->ki_start.tv_sec);

  results.push_back(r);
}

TableRows genProcesses(QueryContext& context) {
  TableRows results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);
  for (unsigned int i = 0; i < cnt; i++) {
    genProcess(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);
  return results;
}

QueryData genProcessEnvs(QueryContext& context) {
  QueryData results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);
  for (unsigned int i = 0; i < cnt; i++) {
    genProcessEnvironment(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);
  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);
  for (unsigned int i = 0; i < cnt; i++) {
    genProcessMap(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);
  return results;
}
}
}
