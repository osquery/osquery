// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>
#include <map>

#include <stdlib.h>
#include <unistd.h>
#include <proc/readproc.h>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

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

std::string proc_name(const proc_t* proc_info) {
  char cmd[17]; // cmd is a 16 char buffer

  memset(cmd, 0, 17);
  memcpy(cmd, proc_info->cmd, 16);
  return std::string(cmd);
}

std::string proc_attr(const std::string& attr, const proc_t* proc_info) {
  std::stringstream filename;

  filename << "/proc/" << proc_info->tid << "/" << attr;
  return filename.str();
}

std::string proc_cmdline(const proc_t* proc_info) {
  std::string attr;
  std::string result;

  attr = proc_attr("cmdline", proc_info);
  std::ifstream fd(attr, std::ios::in | std::ios::binary);
  if (fd) {
    result = std::string(std::istreambuf_iterator<char>(fd),
                         std::istreambuf_iterator<char>());
  }

  return result;
}

std::string proc_link(const proc_t* proc_info) {
  std::string attr;
  std::string result;
  char* link_path;
  long path_max;
  int bytes;

  // The exe is a symlink to the binary on-disk.
  attr = proc_attr("exe", proc_info);
  path_max = pathconf(attr.c_str(), _PC_PATH_MAX);
  link_path = (char*)malloc(path_max);

  memset(link_path, 0, path_max);
  bytes = readlink(attr.c_str(), link_path, path_max);
  if (bytes >= 0) {
    result = std::string(link_path);
  }

  free(link_path);
  return result;
}

std::map<std::string, std::string> proc_env(const proc_t* proc_info) {
  std::map<std::string, std::string> env;
  std::string attr = osquery::tables::proc_attr("environ", proc_info);
  std::string buf;

  std::ifstream fd(attr, std::ios::in | std::ios::binary);

  while (!(fd.fail() || fd.eof())) {
    std::getline(fd, buf, '\0');
    size_t idx = buf.find_first_of("=");

    std::string key = buf.substr(0, idx);
    std::string value = buf.substr(idx + 1);

    env[key] = value;
  }
  return env;
}

/**
 * @brief deallocate the space allocated by readproc if the passed rbuf was NULL
 *
 * @param p The rbuf to free
 */
void standard_freeproc(proc_t* p) {
  if (!p) { // in case p is NULL
    return;
  }
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

QueryData genProcesses() {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  // Populate proc struc for each process.
  while ((proc_info = readproc(proc, NULL))) {
    Row r;

    r["pid"] = boost::lexical_cast<std::string>(proc_info->tid);
    r["uid"] = boost::lexical_cast<std::string>((unsigned int)proc_info->ruid);
    r["gid"] = boost::lexical_cast<std::string>((unsigned int)proc_info->rgid);
    r["euid"] = boost::lexical_cast<std::string>((unsigned int)proc_info->euid);
    r["egid"] = boost::lexical_cast<std::string>((unsigned int)proc_info->egid);
    r["name"] = proc_name(proc_info);
    r["cmdline"] = proc_cmdline(proc_info);
    r["path"] = proc_link(proc_info);
    r["on_disk"] = osquery::pathExists(r["path"]).toString();

    r["resident_size"] = boost::lexical_cast<std::string>(proc_info->vm_rss);
    r["phys_footprint"] = boost::lexical_cast<std::string>(proc_info->vm_size);
    r["user_time"] = boost::lexical_cast<std::string>(proc_info->utime);
    r["system_time"] = boost::lexical_cast<std::string>(proc_info->stime);
    r["start_time"] = boost::lexical_cast<std::string>(proc_info->start_time);
    r["parent"] = boost::lexical_cast<std::string>(proc_info->ppid);

    results.push_back(r);
    standard_freeproc(proc_info);
  }

  closeproc(proc);

  return results;
}

QueryData genProcessEnvs() {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  // Populate proc struc for each process.

  while ((proc_info = readproc(proc, NULL))) {
    auto env = proc_env(proc_info);
    for (auto itr = env.begin(); itr != env.end(); ++itr) {
      Row r;
      r["pid"] = boost::lexical_cast<std::string>(proc_info->tid);
      r["name"] = proc_name(proc_info);
      r["path"] = proc_link(proc_info);
      r["key"] = itr->first;
      r["value"] = itr->second;
      results.push_back(r);
    }

    standard_freeproc(proc_info);
  }

  closeproc(proc);

  return results;
}

QueryData genProcessOpenFiles() {
  QueryData results;
  return results;
}
}
}
