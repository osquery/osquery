// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/tables/implementations/processes.h"

#include <vector>
#include <string>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include <libproc.h>
#include <stdlib.h>

#include "osquery/core.h"

using namespace osquery::core;
using namespace osquery::db;

namespace osquery { namespace tables {

QueryData genProcesses() {
  QueryData results;

  int MAX_PIDS = 4096;
  pid_t pids[MAX_PIDS];
  bzero(pids, MAX_PIDS);
  auto num_pids = proc_listpids(PROC_ALL_PIDS, 0, pids, MAX_PIDS);
  for (auto i : pids) {
    if (i == 0) {
      continue;
    }

    char path[PROC_PIDPATHINFO_MAXSIZE];
    bzero(path, PROC_PIDPATHINFO_MAXSIZE);
    proc_pidpath(i, path, sizeof(path));

    char name[1024];
    bzero(name, 1024);
    proc_name(i, name, sizeof(name));

    Row r;
    r["name"] = std::string(name);
    r["path"] = std::string(path);
    r["pid"] = boost::lexical_cast<std::string>(i);
    if (strlen(path) > 0) {
      if (!boost::filesystem::exists(r["path"])) {
        r["on_disk"] = "0";
      } else {
        r["on_disk"] = "1";
      }
    } else {
      r["on_disk"] = "1";
    }
    results.push_back(r);
  }
  if (num_pids <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return {};
  }
  return results;
}

}}
