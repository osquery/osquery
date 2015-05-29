/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <map>

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <paths.h>

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/user.h>
#include <libprocstat.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/tables/system/freebsd/procstat.h"

namespace osquery {
namespace tables {

void genProcessEnvironment(struct procstat* pstat,
                           struct kinfo_proc* proc,
                           QueryData& results) {
  char** envs;
  unsigned int i;

  envs = procstat_getenvv(pstat, proc, 0);
  if (envs != nullptr) {
    for (i = 0; envs[i] != NULL; i++) {
      Row r;
      size_t idx;
      std::string buf = std::string(envs[i]);

      r["pid"] = INTEGER(proc->ki_pid);

      idx = buf.find_first_of("=");
      r["key"] = buf.substr(0, idx);
      r["value"] = buf.substr(idx + 1);
      results.push_back(r);
    }

    procstat_freeenvv(pstat);
  }
}

void genProcessMap(struct procstat* pstat,
                   struct kinfo_proc* proc,
                   QueryData& results) {
  struct kinfo_vmentry* vmentry;
  unsigned int i;
  unsigned int cnt = 0;

  vmentry = procstat_getvmmap(pstat, proc, &cnt);
  if (vmentry != nullptr) {
    for (i = 0; i < cnt; i++) {
      Row r;

      r["pid"] = INTEGER(proc->ki_pid);
      r["path"] = TEXT(vmentry[i].kve_path);
      r["device"] = TEXT(vmentry[i].kve_vn_rdev);
      r["inode"] = INTEGER(vmentry[i].kve_vn_fileid);
      r["offset"] = INTEGER(vmentry[i].kve_offset);

      // To match the linux implementation, convert to hex.
      char addr_str[17] = {0};
      sprintf(addr_str, "%016lx", vmentry[i].kve_start);
      r["start"] = "0x" + TEXT(addr_str);
      sprintf(addr_str, "%016lx", vmentry[i].kve_end);
      r["end"] = "0x" + TEXT(addr_str);

      std::string permissions;
      permissions += (vmentry[i].kve_protection & KVME_PROT_READ) ? "r" : "-";
      permissions += (vmentry[i].kve_protection & KVME_PROT_WRITE) ? "w" : "-";
      permissions += (vmentry[i].kve_protection & KVME_PROT_EXEC) ? "x" : "-";
      // COW is stored as a flag on FreeBSD, but osquery lumps it in the
      // permissions column.
      permissions += (vmentry[i].kve_flags & KVME_FLAG_COW) ? "p" : "-";
      r["permissions"] = TEXT(permissions);

      if (vmentry[i].kve_vn_fileid == 0 && r["path"].size() > 0) {
        r["pseudo"] = INTEGER("1");
      } else {
        r["pseudo"] = INTEGER("0");
      }

      results.push_back(r);
    }

    procstat_freevmmap(pstat, vmentry);
  }
}

void genProcess(struct procstat* pstat,
                struct kinfo_proc* proc,
                QueryData& results) {
  Row r;
  static char path[PATH_MAX];
  char** args;
  struct filestat_list* files = nullptr;
  struct filestat* file = nullptr;
  struct kinfo_vmentry* vmentry = nullptr;
  unsigned int i;
  unsigned int cnt = 0;
  unsigned int pages = 0;

  r["pid"] = INTEGER(proc->ki_pid);
  r["parent"] = INTEGER(proc->ki_ppid);
  r["name"] = TEXT(proc->ki_comm);
  r["uid"] = INTEGER(proc->ki_ruid);
  r["euid"] = INTEGER(proc->ki_svuid);
  r["gid"] = INTEGER(proc->ki_rgid);
  r["egid"] = INTEGER(proc->ki_svgid);

  if (procstat_getpathname(pstat, proc, path, sizeof(path)) == 0) {
    r["path"] = TEXT(path);
    // If the path of the executable that started the process is available and
    // the path exists on disk, set on_disk to 1. If the path is not
    // available, set on_disk to -1. If, and only if, the path of the
    // executable is available and the file does NOT exist on disk, set on_disk
    // to 0.
    r["on_disk"] = TEXT(osquery::pathExists(r["path"]).toString());
  }

  args = procstat_getargv(pstat, proc, 0);
  if (args != nullptr) {
    for (i = 0; args[i] != NULL; i++) {
      r["cmdline"] += TEXT(args[i]);
      // Need to add spaces between arguments, except last one.
      if (args[i + 1] != NULL) {
        r["cmdline"] += TEXT(" ");
      }
    }

    procstat_freeargv(pstat);
  }

  files = procstat_getfiles(pstat, proc, 0);
  if (files != nullptr) {
    STAILQ_FOREACH(file, files, next) {
      if (file->fs_uflags & PS_FST_UFLAG_CDIR) {
        r["cwd"] = TEXT(file->fs_path);
      }
      else if (file->fs_uflags & PS_FST_UFLAG_RDIR) {
        r["root"] = TEXT(file->fs_path);
      }
    }

    procstat_freefiles(pstat, files);
  }

  vmentry = procstat_getvmmap(pstat, proc, &cnt);
  if (vmentry != nullptr) {
    // Add up all the resident pages for each vmmap entry.
    for (i = 0; i < cnt; i++) {
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

QueryData genProcesses(QueryContext& context) {
  QueryData results;
  struct kinfo_proc* procs = nullptr;
  struct procstat* pstat = nullptr;

  auto cnt = getProcesses(context, &pstat, &procs);

  for (size_t i = 0; i < cnt; i++) {
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

  for (size_t i = 0; i < cnt; i++) {
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

  for (size_t i = 0; i < cnt; i++) {
    genProcessMap(pstat, &procs[i], results);
  }

  procstatCleanup(pstat, procs);
  return results;
}
}
}
