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
#include <fstream>
#include <map>

#include <stdlib.h>
#include <unistd.h>
#include <proc/readproc.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

#ifdef PROC_EDITCMDLCVT
/// EDITCMDLCVT is available in libprocps3-dev
#define PROC_SELECTS                                                 \
  PROC_FILLCOM | PROC_EDITCMDLCVT | PROC_FILLMEM | PROC_FILLSTATUS | \
      PROC_FILLSTAT
#else
#define PROC_SELECTS \
  PROC_FILLCOM | PROC_FILLMEM | PROC_FILLSTATUS | PROC_FILLSTAT
#endif

std::string getProcName(const proc_t* proc_info) {
  return std::string(proc_info->cmd);
}

std::string getProcAttr(const std::string& attr, const proc_t* proc_info) {
  return "/proc/" + std::to_string(proc_info->tid) + "/" + attr;
}

std::string readProcCMDLine(const proc_t* proc_info) {
  auto attr = getProcAttr("cmdline", proc_info);

  std::string result;
  std::ifstream fd(attr, std::ios::in | std::ios::binary);
  if (fd) {
    result = std::string(std::istreambuf_iterator<char>(fd),
                         std::istreambuf_iterator<char>());
    std::replace_if(
      result.begin(),
      result.end(),
      [](const char& c) { return c == 0; },
      ' ');
  }

  return result;
}

std::string readProcLink(const proc_t* proc_info) {
  // The exe is a symlink to the binary on-disk.
  auto attr = getProcAttr("exe", proc_info);
  long path_max = pathconf(attr.c_str(), _PC_PATH_MAX);
  auto link_path = (char*)malloc(path_max);
  memset(link_path, 0, path_max);

  std::string result;
  int bytes = readlink(attr.c_str(), link_path, path_max);
  if (bytes >= 0) {
    result = std::string(link_path);
  }

  free(link_path);
  return result;
}

void genProcessEnvironment(const proc_t* proc_info, QueryData& results) {
  auto attr = getProcAttr("environ", proc_info);

  std::ifstream fd(attr, std::ios::in | std::ios::binary);
  std::string buf;
  while (!(fd.fail() || fd.eof())) {
    std::getline(fd, buf, '\0');
    size_t idx = buf.find_first_of("=");

    Row r;
    r["pid"] = INTEGER(proc_info->tid);
    r["key"] = buf.substr(0, idx);
    r["value"] = buf.substr(idx + 1);
    results.push_back(r);
  }
}

void genProcessMap(const proc_t* proc_info, QueryData& results) {
  auto map = getProcAttr("maps", proc_info);

  std::ifstream fd(map, std::ios::in | std::ios::binary);
  std::string line;
  while (!(fd.fail() || fd.eof())) {
    std::getline(fd, line, '\n');
    auto fields = osquery::split(line, " ");

    Row r;
    r["pid"] = INTEGER(proc_info->tid);

    // If can't read address, not sure.
    if (fields.size() < 5) {
      continue;
    }

    if (fields[0].size() > 0) {
      auto addresses = osquery::split(fields[0], "-");
      r["start"] = "0x" + addresses[0];
      r["end"] = "0x" + addresses[1];
    }

    r["permissions"] = fields[1];
    r["offset"] = BIGINT(std::stoll(fields[2], nullptr, 16));
    r["device"] = fields[3];
    r["inode"] = fields[4];

    // Path name must be trimmed.
    if (fields.size() > 5) {
      boost::trim(fields[5]);
      r["path"] = fields[5];
    }

    // BSS with name in pathname.
    r["is_pseudo"] = (fields[4] == "0" && r["path"].size() > 0) ? "1" : "0";
    results.push_back(r);
  }
}

/**
 * @brief deallocate the space allocated by readproc if the passed rbuf was NULL
 *
 * @param p The rbuf to free
 */
void standardFreeproc(proc_t* p) {
  if (!p) { // in case p is NULL
    return;
  }

#ifdef PROC_EDITCMDLCVT
  freeproc(p);
  return;
#endif

  // ptrs are after strings to avoid copying memory when building them.
  // so free is called on the address of the address of strvec[0].
  if (p->cmdline) {
    free((void*)*p->cmdline);
  }
  if (p->environ) {
    free((void*)*p->environ);
  }
  free(p);
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  // Populate proc struc for each process.
  while ((proc_info = readproc(proc, NULL))) {
    if (!context.constraints["pid"].matches<int>(proc_info->tid)) {
      // Optimize by not searching when a pid is a constraint.
      standard_freeproc(proc_info);
      continue;
    }

    Row r;
    r["pid"] = INTEGER(proc_info->tid);
    r["uid"] = BIGINT((unsigned int)proc_info->ruid);
    r["gid"] = BIGINT((unsigned int)proc_info->rgid);
    r["euid"] = BIGINT((unsigned int)proc_info->euid);
    r["egid"] = BIGINT((unsigned int)proc_info->egid);
    r["name"] = getProcName(proc_info);
    std::string cmdline = readProcCMDLine(proc_info);
    boost::algorithm::trim(cmdline);
    r["cmdline"] = cmdline;
    r["path"] = readProcLink(proc_info);
    r["on_disk"] = osquery::pathExists(r["path"]).toString();

    r["resident_size"] = INTEGER(proc_info->vm_rss);
    r["phys_footprint"] = INTEGER(proc_info->vm_size);
    r["user_time"] = INTEGER(proc_info->utime);
    r["system_time"] = INTEGER(proc_info->stime);
    r["start_time"] = INTEGER(proc_info->start_time);
    r["parent"] = INTEGER(proc_info->ppid);

    results.push_back(r);
    standardFreeproc(proc_info);
  }

  closeproc(proc);

  return results;
}

QueryData genProcessEnvs(QueryContext& context) {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  // Populate proc struc for each process.
  while ((proc_info = readproc(proc, NULL))) {
    genProcessEnvironment(proc_info, results);
    standardFreeproc(proc_info);
  }

  closeproc(proc);

  return results;
}

QueryData genProcessMemoryMap(QueryContext& context) {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  while ((proc_info = readproc(proc, NULL))) {
    genProcessMap(proc_info, results);
    standardFreeproc(proc_info);
  }

  closeproc(proc);

  return results;
}
}
}
