// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/system/processes.h"

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>

#include <libproc.h>
#include <stdlib.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery { namespace tables {

QueryData genProcesses() {
  QueryData results;
  std::unordered_set<int> processed;
  std::unordered_map<int, int> parent_pid;

  // find how how many pids there are so that we can create an appropriately
  // sized data structure to store them
  int num_pids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
  if (num_pids <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return {};
  }

  // arbitrarily create a list with 2x capacity in case more processes have
  // been loaded since the last proc_listpids was executed
  pid_t pids[num_pids * 2];
  memset(pids, 0, sizeof(pids));
  int s = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  if (s <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return {};
  }

  for (const auto& pid : pids) {
    pid_t children[num_pids * 2];
    memset(children, 0, sizeof(children));
    proc_listchildpids(pid, children, sizeof(children));
    for (const auto& child : children) {
      parent_pid[child] = pid;
    }
  }

  for (const auto& pid : pids) {
    // if the pid is negative or 0, it doesn't represent a real process so
    // continue the iterations so that we don't add it to the results set
    if (pid <= 0) {
      continue;
    }

    // ensure that we process a pid once and only once
    if (std::find(processed.begin(), processed.end(), pid) != processed.end()) {
      continue;
    }
    processed.insert(pid);

    // gather column data
    Row r;

    const auto parent_it = parent_pid.find(pid);
    if (parent_it != parent_pid.end()) {
      r["parent"] = boost::lexical_cast<std::string>(parent_it->second);
    } else {
      r["parent"] = "-1";
    }

    // process id
    r["pid"] = boost::lexical_cast<std::string>(pid);

    // process name
    char name[1024];
    memset(name, 0, 1024);
    proc_name(pid, name, sizeof(name));
    r["name"] = std::string(name);

    // if the path of the executable that started the process is available and
    // the path exists on disk, set on_disk to 1.  if the path is not
    // available, set on_disk to -1.  if, and only if, the path of the
    // executable is available and the file does not exist on disk, set on_disk
    // to 0.
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    proc_pidpath(pid, path, sizeof(path));
    r["path"] = std::string(path);
    if (strlen(path) > 0) {
      if (!boost::filesystem::exists(r["path"])) {
        r["on_disk"] = "0";
      } else {
        r["on_disk"] = "1";
      }
    } else {
      r["on_disk"] = "-1";
    }

    // systems usage and time information
    struct rusage_info_v2 rusage_info_data;
    int rusage_status = proc_pid_rusage(
      pid, RUSAGE_INFO_V2, (rusage_info_t*)&rusage_info_data);
    // proc_pid_rusage returns -1 if it was unable to gather information
    if (rusage_status == 0) {
      // size information
      r["wired_size"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_wired_size);
      r["resident_size"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_resident_size);
      r["phys_footprint"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_phys_footprint);

      // time information
      r["user_time"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_user_time);
      r["system_time"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_system_time);
      r["start_time"] = boost::lexical_cast<std::string>(
        rusage_info_data.ri_proc_start_abstime);
    }

    // save the results
    results.push_back(r);
  }

  return results;
}

}}
