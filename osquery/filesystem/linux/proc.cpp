/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <linux/limits.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/linux/proc.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
const std::vector<std::string> kUserNamespaceList = {
    "cgroup", "ipc", "mnt", "net", "pid", "user", "uts"};

Status procGetNamespaceInode(ino_t& inode,
                             const std::string& namespace_name,
                             const std::string& process_namespace_root) {
  inode = 0;

  auto path = process_namespace_root + "/" + namespace_name;

  char link_destination[PATH_MAX] = {};
  auto link_dest_length = readlink(path.data(), link_destination, PATH_MAX - 1);
  if (link_dest_length < 0) {
    return Status(1, "Failed to retrieve the inode for namespace " + path);
  }

  // The link destination must be in the following form: namespace:[inode]
  if (std::strncmp(link_destination,
                   namespace_name.data(),
                   namespace_name.size()) != 0 ||
      std::strncmp(link_destination + namespace_name.size(), ":[", 2) != 0) {
    return Status(1, "Invalid descriptor for namespace " + path);
  }

  // Parse the inode part of the string; strtoull should return us a pointer
  // to the closing square bracket
  const char* inode_string_ptr = link_destination + namespace_name.size() + 2;
  char* square_bracket_ptr = nullptr;

  inode = static_cast<ino_t>(
      std::strtoull(inode_string_ptr, &square_bracket_ptr, 10));
  if (inode == 0 || square_bracket_ptr == nullptr ||
      *square_bracket_ptr != ']') {
    return Status(1, "Invalid inode value in descriptor for namespace " + path);
  }

  return Status::success();
}

Status procGetProcessNamespaces(const std::string& process_id,
                                ProcessNamespaceList& namespace_list,
                                std::vector<std::string> namespaces) {
  namespace_list.clear();

  if (namespaces.empty()) {
    namespaces = kUserNamespaceList;
  }

  auto process_namespace_root = kLinuxProcPath + "/" + process_id + "/ns";

  for (const auto& namespace_name : namespaces) {
    ino_t namespace_inode;
    auto status = procGetNamespaceInode(
        namespace_inode, namespace_name, process_namespace_root);
    if (!status.ok()) {
      continue;
    }

    namespace_list[namespace_name] = namespace_inode;
  }

  return Status::success();
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

unsigned short procDecodeUnsignedShortFromHex(
    const std::string& hex_encoded_short) {
  unsigned short decoded = 0;
  if (hex_encoded_short.length() == 4) {
    sscanf(hex_encoded_short.c_str(), "%hX", &decoded);
  }
  return decoded;
}

// Retrieve AF_PACKET sockets out of /proc/net/packet
// if protocol is set to non 0, return only sockets for this protocol;
// else, all.
Status procGetSocketListPacket(int family,
                               int protocol,
                               ino_t net_ns,
                               const std::string& content,
                               SocketInfoList& result) {
  // The system's socket information is tokenized by line.
  bool header = true;
  int decoded_protocol;

  for (const auto& line : osquery::split(content, "\n")) {
    if (header) {
      if (line.find("sl") != 0 && line.find("sk") != 0) {
        return Status::failure(
            "Invalid file header when reading packet sockets file contents");
      }
      header = false;
      continue;
    }

    auto fields = osquery::split(line, " ");
    if (fields.size() < 9) {
      VLOG(1) << "Invalid socket descriptor found: '" << line
              << "'. Skipping this entry";
      continue;
    }

    decoded_protocol =
        procDecodeUnsignedShortFromHex(fields[kPacketLineProtocolIndex]);
    if (protocol > 0 && decoded_protocol != protocol) {
      // filter unwanted entry.
      continue;
    }

    SocketInfo socket_info = {};
    socket_info.family = family;
    socket_info.net_ns = net_ns;
    socket_info.socket = fields[kPacketLineInodeIndex];
    socket_info.protocol = decoded_protocol;
    socket_info.state = kSocketStateNone;

    result.push_back(std::move(socket_info));
  }

  return Status::success();
}

static Status procGetSocketListInet(int family,
                                    int protocol,
                                    ino_t net_ns,
                                    const std::string& path,
                                    const std::string& content,
                                    SocketInfoList& result) {
  // The system's socket information is tokenized by line.
  bool header = true;
  for (const auto& line : osquery::split(content, "\n")) {
    if (header) {
      if (line.find("sl") != 0 && line.find("sk") != 0) {
        return Status(1, std::string("Invalid file header for ") + path);
      }
      header = false;
      continue;
    }

    // The socket information is tokenized by spaces, each a field.
    auto fields = osquery::split(line, " ");
    if (fields.size() < 10) {
      VLOG(1) << "Invalid socket descriptor found: '" << line
              << "'. Skipping this entry";
      continue;
    }

    // Two of the fields are the local/remote address/port pairs.
    auto locals = osquery::split(fields[1], ":");
    auto remotes = osquery::split(fields[2], ":");

    if (locals.size() != 2 || remotes.size() != 2) {
      VLOG(1) << "Invalid socket descriptor found: '" << line
              << "'. Skipping this entry";
      continue;
    }

    SocketInfo socket_info = {};
    socket_info.socket = fields[9];
    socket_info.net_ns = net_ns;
    socket_info.family = family;
    socket_info.protocol = protocol;
    socket_info.local_address = procDecodeAddressFromHex(locals[0], family);
    socket_info.local_port = procDecodeUnsignedShortFromHex(locals[1]);
    socket_info.remote_address = procDecodeAddressFromHex(remotes[0], family);
    socket_info.remote_port = procDecodeUnsignedShortFromHex(remotes[1]);

    if (protocol == IPPROTO_TCP) {
      char* null_terminator_ptr = nullptr;
      auto integer_socket_state =
          std::strtoull(fields[3].data(), &null_terminator_ptr, 16);
      if (integer_socket_state == 0 ||
          integer_socket_state >= tcp_states.size() ||
          null_terminator_ptr == nullptr || *null_terminator_ptr != 0) {
        socket_info.state = "UNKNOWN";
      } else {
        socket_info.state = tcp_states[integer_socket_state];
      }
    }

    result.push_back(std::move(socket_info));
  }

  return Status(0);
}

static Status procGetSocketListUnix(ino_t net_ns,
                                    const std::string& path,
                                    const std::string& content,
                                    SocketInfoList& result) {
  // The system's socket information is tokenized by line.
  bool header = true;
  for (const auto& line : osquery::split(content, "\n")) {
    if (header) {
      if (line.find("Num") != 0) {
        return Status(1, std::string("Invalid file header for ") + path);
      }
      header = false;
      continue;
    }

    // The socket information is tokenized by spaces, each a field.
    auto fields = osquery::split(line, " ");
    if (fields.size() < 7) {
      VLOG(1) << "Invalid UNIX socket descriptor found: '" << line
              << "'. Skipping this entry";
      continue;
    }

    SocketInfo socket_info = {};
    socket_info.socket = fields[6];
    socket_info.net_ns = net_ns;
    socket_info.family = AF_UNIX;
    socket_info.protocol = std::atoll(fields[2].data());
    socket_info.unix_socket_path = (fields.size() >= 8) ? fields[7] : "";

    result.push_back(std::move(socket_info));
  }

  return Status(0);
}

Status procGetSocketList(int family,
                         int protocol,
                         ino_t net_ns,
                         const std::string& pid,
                         SocketInfoList& result) {
  std::string path = kLinuxProcPath + "/" + pid + "/net/";

  switch (family) {
  case AF_INET:
    if (kLinuxProtocolNames.count(protocol) == 0) {
      return Status(
          1,
          "Invalid family " + std::to_string(protocol) + " for AF_INET family");
    } else {
      path += kLinuxProtocolNames.at(protocol);
    }
    break;

  case AF_INET6:
    if (kLinuxProtocolNames.count(protocol) == 0) {
      return Status(1,
                    "Invalid protocol " + std::to_string(protocol) +
                        " for AF_INET6 family");
    } else {
      path += kLinuxProtocolNames.at(protocol) + "6";
    }
    break;

  case AF_UNIX:
    if (protocol != IPPROTO_IP) {
      return Status(1,
                    "Invalid protocol " + std::to_string(protocol) +
                        " for AF_UNIX family");
    } else {
      path += "unix";
    }

    break;
  case AF_PACKET:
    path += kPacketPathSuffix;
    break;

  default:
    return Status(1, "Invalid family " + std::to_string(family));
  }

  std::string content;
  if (!osquery::readFile(path, content).ok()) {
    return Status(1, "Could not open socket information from " + path);
  }

  Status status(0);
  switch (family) {
  case AF_INET:
  case AF_INET6:
    status =
        procGetSocketListInet(family, protocol, net_ns, path, content, result);
    break;

  case AF_PACKET:
    status = procGetSocketListPacket(family, protocol, net_ns, content, result);
    break;

  case AF_UNIX:
    status = procGetSocketListUnix(net_ns, path, content, result);
    break;
  }

  return status;
}

Status procGetSocketInodeToProcessInfoMap(const std::string& pid,
                                          SocketInodeToProcessInfoMap& result) {
  auto callback = [](const std::string& _pid,
                     const std::string& fd,
                     const std::string& link,
                     SocketInodeToProcessInfoMap& _result) -> bool {
    /* We only care about sockets. But there will be other descriptors. */
    if (link.find("socket:[") != 0) {
      return true;
    }

    std::string inode = link.substr(8, link.size() - 9);
    _result[inode] = {_pid, fd};
    return true;
  };

  return procEnumerateProcessDescriptors<decltype(result)>(
      pid, result, callback);
}

Status procProcesses(std::set<std::string>& processes) {
  auto callback = [](const std::string& pid,
                     std::set<std::string>& _processes) -> bool {
    _processes.insert(pid);
    return true;
  };

  return procEnumerateProcesses<decltype(processes)>(processes, callback);
}

Status procDescriptors(const std::string& process,
                       std::map<std::string, std::string>& descriptors) {
  auto callback = [](const std::string& pid,
                     const std::string& fd,
                     const std::string& link_name,
                     std::map<std::string, std::string>& _descriptors) -> bool {
    _descriptors[fd] = link_name;
    return true;
  };

  return procEnumerateProcessDescriptors<decltype(descriptors)>(
      process, descriptors, callback);
}

Status procReadDescriptor(const std::string& process,
                          const std::string& descriptor,
                          std::string& result) {
  auto link = kLinuxProcPath + "/" + process + "/fd/" + descriptor;

  char result_path[PATH_MAX] = {0};
  auto size = readlink(link.c_str(), result_path, sizeof(result_path) - 1);
  if (size >= 0) {
    result = std::string(result_path);
    return Status(0);
  } else {
    return Status(1, "Could not call readlink: " + kLinuxProcPath);
  }
}

} // namespace osquery
