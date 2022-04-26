/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/linux/proc.h>

namespace osquery {
namespace tables {

QueryData genOpenSockets(QueryContext& context) {
  Status status;
  QueryData results;

  /*
   * If filtering by pid, restrict results to the list of pids provided
   * otherwise query all pids from the system and also report on sockets without
   * an associated pid.
   */
  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  }

  bool pid_filter = !(pids.empty() ||
                      std::find(pids.begin(), pids.end(), "-1") != pids.end());

  if (!pid_filter) {
    pids.clear();
    status = osquery::procProcesses(pids);
    if (!status.ok()) {
      VLOG(1) << "Failed to acquire pid list: " << status.what();
      return results;
    }
  }

  /* Data for this table is fetched from 3 different sources and correlated.
   *
   * 1. Collect all sockets associated with each pid by going through all files
   * under /proc/<pid>/fd and search for links of the type socket:[<inode>].
   * Extract the inode and fd (filename) and index it by inode number. The inode
   * can then be used to correlate pid and fd with the socket information
   * collected on step 3. The map generated in this step will only contain
   * sockets associated with pids in the list, so it will also be used to filter
   * the sockets later if pid_filter is set.
   *
   * 2. Collect the inode for the network namespace associated with each pid.
   * Every time a new namespace is found execute step 3 to get socket basic
   * information.
   *
   * 3. Collect basic socket information for all sockets under a specifc network
   * namespace. This is done by reading through files under /proc/<pid>/net for
   * the first pid we find in a certain namespace. Notice this will collect
   * information for all sockets on the namespace not only for sockets
   * associated with the specific pid, therefore only needs to be run once. From
   * this step we collect the inodes of each of the sockets, and will use that
   * to correlate the socket information with the information collect on steps
   * 1 and 2.
   */

  /* Use a set to record the namespaces already processed */
  std::set<ino_t> netns_list;
  SocketInodeToProcessInfoMap inode_proc_map;
  SocketInfoList socket_list;
  for (const auto& pid : pids) {
    /* Step 1 */
    status = procGetSocketInodeToProcessInfoMap(pid, inode_proc_map);
    if (!status.ok()) {
      VLOG(1) << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire socket inode to process map for pid "
              << pid << ": " << status.what();
    }

    /* Step 2 */
    ino_t ns;
    ProcessNamespaceList namespaces;
    status = procGetProcessNamespaces(pid, namespaces, {"net"});
    if (status.ok()) {
      ns = namespaces["net"];
    } else {
      /* If namespaces are not available we allways set ns to 0 and step 3 will
       * run once for the first pid in the list.
       */
      ns = 0;
      VLOG(1) << "Results for the process_open_sockets might be incomplete."
                 "Failed to acquire network namespace information for process "
                 "with pid "
              << pid << ": " << status.what();
    }

    if (netns_list.count(ns) == 0) {
      netns_list.insert(ns);

      /* Step 3 */
      for (const auto& pair : kLinuxProtocolNames) {
        status = procGetSocketList(AF_INET, pair.first, ns, pid, socket_list);
        if (!status.ok()) {
          VLOG(1)
              << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire basic socket information for AF_INET "
              << pair.second << ": " << status.what();
        }

        status = procGetSocketList(AF_INET6, pair.first, ns, pid, socket_list);
        if (!status.ok()) {
          VLOG(1)
              << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire basic socket information for AF_INET6 "
              << pair.second << ": " << status.what();
        }
      }
      status = procGetSocketList(AF_UNIX, IPPROTO_IP, ns, pid, socket_list);
      if (!status.ok()) {
        VLOG(1)
            << "Results for process_open_sockets might be incomplete. Failed "
               "to acquire basic socket information for AF_UNIX: "
            << status.what();
      }

      // protocol is 0, we want all protocols here.
      status = procGetSocketList(AF_PACKET, 0, ns, pid, socket_list);
      if (!status.ok()) {
        VLOG(1)
            << "Results for process_open_sockets might be incomplete. Failed "
               "to acquire basic socket information for AF_PACKET: "
            << status.what();
      }
    }
  }

  /* Finally correlate all the information. Go through all the sockets
   * collected on step 3 and correlate that with the pid and fd collected from
   * step 1. If filtering only take sockets for which the inode is available on
   * the inode to process information map.
   */
  for (const auto& info : socket_list) {
    Row r;
    auto proc_it = inode_proc_map.find(info.socket);
    if (proc_it != inode_proc_map.end()) {
      r["pid"] = proc_it->second.pid;
      r["fd"] = proc_it->second.fd;
    } else if (!pid_filter) {
      r["pid"] = "-1";
      r["fd"] = "-1";
    } else {
      /* If we're filtering by pid we only care about sockets associated with
       * pids on the list.*/
      continue;
    }

    r["socket"] = info.socket;
    r["family"] = std::to_string(info.family);
    r["protocol"] = std::to_string(info.protocol);
    r["local_address"] = info.local_address;
    r["local_port"] = std::to_string(info.local_port);
    r["remote_address"] = info.remote_address;
    r["remote_port"] = std::to_string(info.remote_port);
    r["path"] = info.unix_socket_path;
    r["state"] = info.state;
    r["net_namespace"] = std::to_string(info.net_ns);

    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
