/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <linux/limits.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/filesystem/linux/proc.h"

namespace osquery {
const char* kLinuxProcPath = "/proc";

Status procGetProcessNamespaces(const std::string& process_id,
                                ProcessNamespaceList& namespace_list) {
  namespace_list.clear();

  for (std::string namespace_name :
       {"cgroup", "ipc", "mnt", "net", "pid", "user", "uts"}) {
    std::string symlink_path = std::string(kLinuxProcPath) + "/" + process_id +
                               "/ns/" + namespace_name;

    char link_destination[PATH_MAX] = {};
    auto link_dest_length =
        readlink(symlink_path.data(), link_destination, PATH_MAX - 1);
    if (link_dest_length < 0) {
      return Status(1,
                    std::string("Failed to retrieve the inode for namespace ") +
                        namespace_name + " in process " + process_id);
    }

    // The link destination must be in the following form: namespace:[inode]
    if (std::strncmp(link_destination,
                     namespace_name.data(),
                     namespace_name.size()) != 0 ||
        std::strncmp(link_destination + namespace_name.size(), ":[", 2) != 0) {
      return Status(1,
                    std::string("Invalid descriptor for namespace ") +
                        namespace_name + " in process " + process_id);
    }

    // Parse the inode part of the string; strtoull should return us a pointer
    // to the
    // closing square bracket
    const char* inode_string_ptr = link_destination + namespace_name.size() + 2;
    char* square_bracket_ptr = nullptr;

    auto inode = static_cast<ino_t>(
        std::strtoull(inode_string_ptr, &square_bracket_ptr, 10));
    if (inode == 0 || square_bracket_ptr == nullptr ||
        *square_bracket_ptr != ']') {
      return Status(
          1,
          std::string("Invalid inode value in descriptor for namespace ") +
              namespace_name + " in process " + process_id);
    }

    namespace_list[namespace_name] = inode;
  }

  return Status(0, "OK");
}

std::string procDecodeAddressFromHex(const std::string& encoded_address,
                                     int family) {
  char addr_buffer[INET6_ADDRSTRLEN] = {0};
  if (family == AF_INET) {
    struct in_addr decoded;
    if (encoded_address.length() == 8) {
      sscanf(encoded_address.c_str(), "%X", &(decoded.s_addr));
      inet_ntop(AF_INET, &decoded, addr_buffer, INET_ADDRSTRLEN);
    }
  } else if (family == AF_INET6) {
    struct in6_addr decoded;
    if (encoded_address.length() == 32) {
      sscanf(encoded_address.c_str(),
             "%8x%8x%8x%8x",
             (unsigned int*)&(decoded.s6_addr[0]),
             (unsigned int*)&(decoded.s6_addr[4]),
             (unsigned int*)&(decoded.s6_addr[8]),
             (unsigned int*)&(decoded.s6_addr[12]));
      inet_ntop(AF_INET6, &decoded, addr_buffer, INET6_ADDRSTRLEN);
    }
  }

  return std::string(addr_buffer);
}

unsigned short procDecodePortFromHex(const std::string& encoded_port) {
  unsigned short decoded = 0;
  if (encoded_port.length() == 4) {
    sscanf(encoded_port.c_str(), "%hX", &decoded);
  }
  return decoded;
}

Status procProcesses(std::set<std::string>& processes) {
  auto L_procProcessesCallback = [](const std::string& process_id,
                                    std::set<std::string>& processes) -> bool {
    processes.insert(process_id);
    return true;
  };

  return procProcesses<decltype(processes)>(L_procProcessesCallback, processes);
}

Status procProcessSockets(std::vector<ProcessSocket>& socket_list,
                          const std::string& process_id,
                          int protocol,
                          int family) {
  socket_list.clear();

  auto L_procProcessSocketsCallback = [](
      const ProcessSocket& proc_socket,
      std::vector<ProcessSocket>& socket_list) -> bool {
    socket_list.push_back(proc_socket);
    return true;
  };

  return procProcessSockets<decltype(socket_list)>(
      L_procProcessSocketsCallback, socket_list, process_id, protocol, family);
}

Status procDescriptors(const std::string& process,
                       std::map<std::string, std::string>& descriptors) {
  auto L_procDescriptorsCallback = [](
      const std::string& fd,
      const std::string& link_name,
      std::map<std::string, std::string>& descriptors) -> bool {

    descriptors[fd] = link_name;
    return true;
  };

  return procDescriptors<decltype(descriptors)>(
      process, L_procDescriptorsCallback, descriptors);
}

Status procSocketInodeToFdMap(
    const std::string& process,
    std::unordered_map<std::string, std::string>& inode_to_fd_map) {
  inode_to_fd_map.clear();

  auto L_procDescriptorsCallback = [](
      const std::string& fd,
      const std::string& link_name,
      std::unordered_map<std::string, std::string>& inode_to_fd_map) -> bool {

    if (link_name.find("socket:[") != 0) {
      return true;
    }

    auto inode = link_name.substr(8, link_name.size() - 9);
    inode_to_fd_map[inode] = fd;

    return true;
  };

  return procDescriptors<decltype(inode_to_fd_map)>(
      process, L_procDescriptorsCallback, inode_to_fd_map);
}

Status procReadDescriptor(const std::string& process,
                          const std::string& descriptor,
                          std::string& result) {
  auto link = std::string(kLinuxProcPath) + "/" + process + "/fd/" + descriptor;

  char result_path[PATH_MAX] = {0};
  auto size = readlink(link.c_str(), result_path, sizeof(result_path) - 1);
  if (size >= 0) {
    result = std::string(result_path);
    return Status(0);
  }
  return Status(1, "Could not read path");
}
}
