// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <fstream>
#include <streambuf>

#include <stdlib.h>
#include <proc/readproc.h>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery {
namespace tables {

#define PROC_SELECTS                                                 \
  PROC_FILLCOM | PROC_EDITCMDLCVT | PROC_FILLMEM | PROC_FILLSTATUS | \
      PROC_FILLSTAT

std::string proc_name(const proc_t* proc_info) {
  char cmd[16];

  memset(cmd, 0, 16);
  memcpy(cmd, proc_info->cmd, 15);
  return std::string(cmd);
}

std::string proc_path(const proc_t* proc_info) {
  std::string path;

  char* filename;

  filename = (char*)malloc(sizeof("/proc//cmdline") + sizeof(int) * 3);
  sprintf(filename, "/proc/%u/cmdline", proc_info->tid);

  std::ifstream fd(filename, std::ios::in | std::ios::binary);
  if (fd) {
    path = std::string(std::istreambuf_iterator<char>(fd),
                       std::istreambuf_iterator<char>());
  }

  free(filename);
  return path;
}

QueryData genProcesses() {
  QueryData results;

  proc_t* proc_info;
  PROCTAB* proc = openproc(PROC_SELECTS);

  // Populate proc struc for each process.
  while (proc_info = readproc(proc, NULL)) {
    Row r;

    r["pid"] = boost::lexical_cast<std::string>(proc_info->tid);
    r["name"] = proc_name(proc_info);
    r["path"] = proc_path(proc_info);
    r["resident_size"] = boost::lexical_cast<std::string>(proc_info->vm_rss);
    r["phys_footprint"] = boost::lexical_cast<std::string>(proc_info->vm_size);
    r["user_time"] = boost::lexical_cast<std::string>(proc_info->utime);
    r["system_time"] = boost::lexical_cast<std::string>(proc_info->stime);
    r["start_time"] = boost::lexical_cast<std::string>(proc_info->start_time);
    r["parent"] = boost::lexical_cast<std::string>(proc_info->ppid);

    results.push_back(r);
    freeproc(proc_info);
  }

  closeproc(proc);

  return results;
}
}
}
