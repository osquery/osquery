/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <limits.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>

namespace osquery {
namespace tables {

static std::string procPath(pid_t pid) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, (int)pid};
  char path[PATH_MAX];
  size_t len = sizeof(path);
  if (sysctl(mib, 4, path, &len, nullptr, 0) != 0 || len == 0) {
    return "";
  }
  // sysctl includes the terminating NUL in len when non-empty.
  if (path[len - 1] == '\0') {
    return std::string(path);
  }
  return std::string(path, len);
}

TableRows genProcesses(QueryContext& context) {
  TableRows results;

  int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC};
  size_t len = 0;
  if (sysctl(mib, 3, nullptr, &len, nullptr, 0) != 0 || len == 0) {
    return results;
  }
  len += len / 8; // 12.5% slack
  std::vector<char> buf(len);
  if (sysctl(mib, 3, buf.data(), &len, nullptr, 0) != 0) {
    return results;
  }

  char* p = buf.data();
  char* end = buf.data() + len;
  long pagesize = getpagesize();

  while (p + sizeof(struct kinfo_proc) <= end) {
    auto* proc = reinterpret_cast<struct kinfo_proc*>(p);
    if (proc->ki_structsize == 0 || proc->ki_structsize > (size_t)(end - p)) {
      break;
    }
    auto r = make_table_row();
    r["pid"] = BIGINT(proc->ki_pid);
    r["name"] = std::string(proc->ki_comm);
    r["path"] = procPath(proc->ki_pid);
    r["cmdline"] = "";
    char st = '?';
    switch (proc->ki_stat) {
    case SRUN:
      st = 'R';
      break;
    case SSLEEP:
      st = 'S';
      break;
    case SSTOP:
      st = 'T';
      break;
    case SZOMB:
      st = 'Z';
      break;
    case SIDL:
      st = 'I';
      break;
    case SWAIT:
      st = 'W';
      break;
    case SLOCK:
      st = 'L';
      break;
    default:
      st = '?';
      break;
    }
    r["state"] = std::string(1, st);
    r["cwd"] = "";
    r["root"] = "";
    r["uid"] = BIGINT(proc->ki_ruid);
    r["gid"] = BIGINT(proc->ki_rgid);
    r["euid"] = BIGINT(proc->ki_uid);
    r["egid"] = BIGINT(proc->ki_rgid);
    r["suid"] = BIGINT(proc->ki_svuid);
    r["sgid"] = BIGINT(proc->ki_svgid);
    r["on_disk"] = INTEGER(-1);
    r["wired_size"] = "0";
    r["resident_size"] = BIGINT((uint64_t)proc->ki_rssize * (uint64_t)pagesize);
    r["total_size"] = BIGINT((uint64_t)proc->ki_size);
    r["user_time"] = BIGINT((uint64_t)proc->ki_rusage.ru_utime.tv_sec * 1000 +
                            (uint64_t)proc->ki_rusage.ru_utime.tv_usec / 1000);
    r["system_time"] =
        BIGINT((uint64_t)proc->ki_rusage.ru_stime.tv_sec * 1000 +
               (uint64_t)proc->ki_rusage.ru_stime.tv_usec / 1000);
    r["disk_bytes_read"] = "0";
    r["disk_bytes_written"] = "0";
    r["start_time"] = BIGINT((int64_t)proc->ki_start.tv_sec);
    r["parent"] = BIGINT(proc->ki_ppid);
    r["pgroup"] = BIGINT(proc->ki_pgid);
    r["threads"] = INTEGER(proc->ki_numthreads);
    r["nice"] = INTEGER((int)proc->ki_nice);
    results.push_back(r);
    p += proc->ki_structsize;
  }
  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  return {};
}

} // namespace tables
} // namespace osquery
