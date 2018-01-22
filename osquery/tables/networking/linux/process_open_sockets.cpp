/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem/linux/proc.h"

namespace osquery {
namespace tables {
QueryData genOpenSockets(QueryContext& context) {
  // If a pid is given then set that as the only item in processes.
  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  struct CallbackData final {
    QueryData results;
    std::string process_id;
    ino_t current_network_namespace;
  };

  auto L_genSocketsFromProcCallback = [](const ProcessSocket& proc_socket,
                                         CallbackData& data) -> bool {
    Row r;
    r["socket"] = proc_socket.socket;
    r["family"] = std::to_string(proc_socket.family);
    r["protocol"] = std::to_string(proc_socket.protocol);
    r["local_address"] = proc_socket.local_address;
    r["local_port"] = std::to_string(proc_socket.local_port);
    r["remote_address"] = proc_socket.remote_address;
    r["remote_port"] = std::to_string(proc_socket.remote_port);
    r["path"] = proc_socket.unix_socket_path;
    r["fd"] = std::to_string(proc_socket.fd);
    r["pid"] = data.process_id;
    r["net_namespace"] = std::to_string(data.current_network_namespace);
    r["state"] = proc_socket.state;

    data.results.push_back(std::move(r));
    return true;
  };

  CallbackData callback_data = {};

  for (const auto& process_id : pids) {
    // We are only interested in the 'net' namespace, so we will be filtering
    // out everything else
    ProcessNamespaceList process_namespaces;
    auto status =
        procGetProcessNamespaces(process_id, process_namespaces, {"net"});
    if (!status.ok()) {
      VLOG(1)
          << "The process_open_sockets may be showing partial results. Error: "
          << status.getMessage();
      continue;
    }

    callback_data.process_id = process_id;
    callback_data.current_network_namespace = process_namespaces["net"];

    std::unordered_map<std::string, std::string> inode_to_fd_map;
    status = procSocketInodeToFdMap(process_id, inode_to_fd_map);
    if (!status.ok()) {
      VLOG(1) << "The process_open_sockets may be showing partial results. "
                 "Error: Failed to enumerate the fd map for the following "
                 "process: "
              << process_id;
    }

    for (const auto& pair : kLinuxProtocolNames) {
      int protocol = pair.first;

      std::vector<ProcessSocket> socket_list;
      status = procProcessSockets<CallbackData&>(L_genSocketsFromProcCallback,
                                                 callback_data,
                                                 process_id,
                                                 protocol,
                                                 AF_INET,
                                                 &inode_to_fd_map);
      if (!status.ok()) {
        VLOG(1) << "The process_open_sockets may be showing partial results. "
                   "Error: "
                << status.getMessage();
      }

      status = procProcessSockets<CallbackData&>(L_genSocketsFromProcCallback,
                                                 callback_data,
                                                 process_id,
                                                 protocol,
                                                 AF_INET6,
                                                 &inode_to_fd_map);
      if (!status.ok()) {
        VLOG(1) << "The process_open_sockets may be showing partial results. "
                   "Error: "
                << status.getMessage();
      }
    }

    status = procProcessSockets<CallbackData&>(L_genSocketsFromProcCallback,
                                               callback_data,
                                               process_id,
                                               IPPROTO_IP,
                                               AF_UNIX,
                                               &inode_to_fd_map);
    if (!status.ok()) {
      VLOG(1) << "The process_open_sockets may be showing partial results. "
                 "Error: "
              << status.getMessage();
    }
  }

  return callback_data.results;
}
} // namespace tables
} // namespace osquery
