// Copyright 2004-present Facebook. All Rights Reserved.

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include <map>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <stdlib.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

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

  // now that we've allocated "pids", let's overwrite num_pids with the actual
  // amount of data that was returned for proc_listpids when we populate the
  // pids data structure
  num_pids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  if (num_pids <= 0) {
    LOG(ERROR) << "An error occured retrieving the process list";
    return {};
  }

  // calculate the parent process of each process and store it in parent_pid
  for (int i = 0; i < num_pids; ++i) {
    pid_t children[num_pids];
    int num_children = proc_listchildpids(pids[i], children, sizeof(children));
    for (int j = 0; j < num_children; j++) {
      parent_pid[children[j]] = pids[i];
    }
  }

  for (int i = 0; i < num_pids; ++i) {
    // if the pid is negative or 0, it doesn't represent a real process so
    // continue the iterations so that we don't add it to the results set
    if (pids[i] <= 0) {
      continue;
    }

    // ensure that we process a pid once and only once
    if (processed.find(pids[i]) != processed.end()) {
      continue;
    }
    processed.insert(pids[i]);

    // gather column data
    Row r;

    const auto parent_it = parent_pid.find(pids[i]);
    if (parent_it != parent_pid.end()) {
      r["parent"] = boost::lexical_cast<std::string>(parent_it->second);
    } else {
      r["parent"] = "-1";
    }

    // process id
    r["pid"] = boost::lexical_cast<std::string>(pids[i]);

    // process name
    char name[1024];
    proc_name(pids[i], name, sizeof(name));
    r["name"] = std::string(name);

    // if the path of the executable that started the process is available and
    // the path exists on disk, set on_disk to 1.  if the path is not
    // available, set on_disk to -1.  if, and only if, the path of the
    // executable is available and the file does not exist on disk, set on_disk
    // to 0.
    char path[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(pids[i], path, sizeof(path));
    r["path"] = std::string(path);
    r["on_disk"] = osquery::pathExists(r["path"]).toString();

    // systems usage and time information
    struct rusage_info_v2 rusage_info_data;
    int rusage_status = proc_pid_rusage(
        pids[i], RUSAGE_INFO_V2, (rusage_info_t*)&rusage_info_data);
    // proc_pid_rusage returns -1 if it was unable to gather information
    if (rusage_status == 0) {
      // size information
      r["wired_size"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_wired_size);
      r["resident_size"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_resident_size);
      r["phys_footprint"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_phys_footprint);

      // time information
      r["user_time"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_user_time);
      r["system_time"] =
          boost::lexical_cast<std::string>(rusage_info_data.ri_system_time);
      r["start_time"] = boost::lexical_cast<std::string>(
          rusage_info_data.ri_proc_start_abstime);
    }

    // save the results
    results.push_back(r);
  }

  return results;
}

void genProcessList(std::vector<int>& pidlist) {
  size_t buf_size;
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

  if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) < 0) {
    perror("Failure calling sysctl");
    return;
  }

  int num_pids = buf_size / sizeof(struct kinfo_proc);
  struct kinfo_proc procs[num_pids];

  pidlist.clear();
  for (int i = 0; i < num_pids; ++i) {
    int pid = procs[i].kp_proc.p_pid;
    if (pid != 0) {
      pidlist.push_back(pid);
    }
  }
}

// Get the max args space
int genMaxArgs() {
  int mib[2] = {CTL_KERN, KERN_ARGMAX};

  int argmax = 0;
  size_t size = sizeof(argmax);
  if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) {
    return 0;
  }

  return argmax;
}

void genProcessEnv(int pid,
                   size_t argmax,
                   std::string& procname,
                   std::map<std::string, std::string>& env) {
  std::vector<std::string> args;
  char procargs[argmax];
  const char* cp = procargs;
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};

  // We clear the env list, just in case its a recycled map
  procname = std::string("");
  env.clear();

  if (sysctl(mib, 3, &procargs, &argmax, NULL, 0) == -1) {
    return;
  }

  // Here we make the assertion that we are interested in all non-empty strings
  // in the proc args+env
  do {
    std::string s = std::string(cp);
    if (s.length() > 0) {
      args.push_back(s);
    }
    cp += args.back().size() + 1;
  } while (cp < procargs + argmax);

  // Since we know that all envs will have an = sign and are at the end of the
  // list,
  // we iterate from the end forward until we stop seeing = signs. According to
  // the
  // ps source, there is no programmatic way to know where args stop and env
  // begins,
  // so args at the end of a command string which contain "=" may erroneously
  // appear
  // as env vars.
  procname = args[1];
  for (auto itr = args.rbegin(); itr < args.rend(); ++itr) {
    size_t idx = itr->find_first_of("=");
    if (idx == std::string::npos) {
      break;
    }
    std::string key = itr->substr(0, idx);
    std::string value = itr->substr(idx + 1);
    env[key] = value;
  }
}

QueryData genProcessEnvs() {
  QueryData results;
  std::vector<int> pidlist;
  std::map<std::string, std::string> env;
  std::string procname;
  int argmax = genMaxArgs();

  genProcessList(pidlist);
  for (auto pid_itr = pidlist.begin(); pid_itr < pidlist.end(); ++pid_itr) {
    genProcessEnv(*pid_itr, argmax, procname, env);
    for (auto env_itr = env.begin(); env_itr != env.end(); ++env_itr) {
      Row r;
      r["pid"] = *pid_itr;
      r["name"] = procname;
      r["key"] = env_itr->first;
      r["value"] = env_itr->second;
    }
  }

  return results;
}
}
}
