/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <unordered_map>

#include <arpa/inet.h>
#include <linux/limits.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

namespace osquery {
const std::string kLinuxProcPath {"/proc"};

struct ProcessSocket final {
  std::string socket;
  int family{0};
  int protocol{0};

  std::string local_address;
  std::uint16_t local_port{0U};

  std::string remote_address;
  std::uint16_t remote_port{0U};

  std::string unix_socket_path;

  int fd{0};
  std::string state;
};

// Linux proc protocol define to net stats file name.
const std::map<int, std::string> kLinuxProtocolNames = {
    {IPPROTO_ICMP, "icmp"},
    {IPPROTO_TCP, "tcp"},
    {IPPROTO_UDP, "udp"},
    {IPPROTO_UDPLITE, "udplite"},
    {IPPROTO_RAW, "raw"},
};

const std::vector<std::string> tcp_states = {"UNKNOWN",
                                             "ESTABLISHED",
                                             "SYN_SENT",
                                             "SYN_RECV",
                                             "FIN_WAIT1",
                                             "FIN_WAIT2",
                                             "TIME_WAIT",
                                             "CLOSE",
                                             "CLOSE_WAIT",
                                             "LAST_ACK",
                                             "LISTEN",
                                             "CLOSING"};

using ProcessNamespaceList = std::map<std::string, ino_t>;

Status procGetProcessNamespaces(
    const std::string& process_id,
    ProcessNamespaceList& namespace_list,
    std::vector<std::string> namespaces = std::vector<std::string>());

Status procReadDescriptor(const std::string& process,
                          const std::string& descriptor,
                          std::string& result);

/// This function parses the inode value in the destination of a user namespace
/// symlink; fail if the namespace name is now what we expect
Status procGetNamespaceInode(ino_t& inode,
                             const std::string& namespace_name,
                             const std::string& process_namespace_root);

std::string procDecodeAddressFromHex(const std::string& encoded_address,
                                     int family);

unsigned short procDecodePortFromHex(const std::string& encoded_port);

Status procSocketInodeToFdMap(
    const std::string& process,
    std::unordered_map<std::string, std::string>& inode_to_fd_map);

template <typename UserData>
Status procProcesses(bool (*callback)(const std::string&, UserData),
                     UserData data) {
  boost::filesystem::directory_iterator it(kLinuxProcPath), end;

  try {
    for (; it != end; ++it) {
      if (!boost::filesystem::is_directory(it->status())) {
        continue;
      }

      // See #792: std::regex is incomplete until GCC 4.9
      const auto& pid = it->path().leaf().string();
      if (std::atoll(pid.data()) <= 0) {
        continue;
      }

      if (!callback(pid, data)) {
        break;
      }
    }

  } catch (const boost::filesystem::filesystem_error& e) {
    VLOG(1) << "Exception iterating Linux processes " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

template <typename UserData>
Status procDescriptors(const std::string& process_id,
                       bool (*callback)(const std::string&,
                                        const std::string&,
                                        UserData),
                       UserData data) {
  auto descriptors_path = kLinuxProcPath + "/" + process_id + "/fd";

  try {
    boost::filesystem::directory_iterator it(descriptors_path), end;

    for (; it != end; ++it) {
      auto fd = it->path().leaf().string();

      std::string linkname;
      if (!procReadDescriptor(process_id, fd, linkname).ok()) {
        continue;
      }

      if (!callback(fd, linkname, data)) {
        break;
      }
    }

    return Status(0, "OK");

  } catch (boost::filesystem::filesystem_error& e) {
    return Status(1,
                  std::string("Cannot access descriptors for ") + process_id);
  }
}

template <typename UserData>
Status procProcessSockets(bool (*callback)(const ProcessSocket&, UserData),
                          UserData user_data,
                          const std::string& process_id,
                          int protocol,
                          int family,
                          std::unordered_map<std::string, std::string>*
                              inode_to_fd_map_ptr = nullptr) {
  if (protocol == IPPROTO_IP && family != AF_UNIX) {
    return Status(
        1, "The IPPROTO_IP protocol can only be used with the AF_UNIX family");
  }

  if (protocol != IPPROTO_IP &&
      kLinuxProtocolNames.find(protocol) == kLinuxProtocolNames.end()) {
    return Status(1, "Invalid protocol specified");
  }

  if (family != AF_UNIX && family != AF_INET && family != AF_INET6) {
    return Status(1, "Invalid address family specified");
  }

  std::unordered_map<std::string, std::string> inode_to_fd_map;
  if (inode_to_fd_map_ptr != nullptr) {
    inode_to_fd_map = *inode_to_fd_map_ptr;
  } else {
    auto status = procSocketInodeToFdMap(process_id, inode_to_fd_map);
    if (!status.ok()) {
      return Status(1, "Failed to enumerate the process descriptors");
    }
  }

  auto socket_list_path = kLinuxProcPath + "/" + process_id + "/net/";

  if (family == AF_UNIX) {
    socket_list_path += "unix";
  } else {
    socket_list_path += kLinuxProtocolNames.at(protocol);
    socket_list_path += (family == AF_INET6) ? "6" : "";
  }

  std::string content;
  if (!osquery::readFile(socket_list_path, content).ok()) {
    return Status(1, "Could not open socket information from /proc");
  }

  // The system's socket information is tokenized by line.
  size_t index = 0;

  for (const auto& line : osquery::split(content, "\n")) {
    if (++index == 1) {
      // The first line is a textual header and will be ignored.
      if (line.find("sl") != 0 && line.find("sk") != 0 &&
          line.find("Num") != 0) {
        return Status(1,
                      std::string("Invalid file header encountered in ") +
                          socket_list_path);
      }

      continue;
    }

    // The socket information is tokenized by spaces, each a field.
    auto fields = osquery::split(line, " ");

    // UNIX socket reporting has a smaller number of fields.
    size_t min_fields = (family == AF_UNIX) ? 7 : 10;
    if (fields.size() < min_fields) {
      VLOG(1) << "Invalid UNIX socket descriptor found: '" << line
              << "'. Skipping this entry";
      continue;
    }

    ProcessSocket proc_socket = {};

    if (family == AF_UNIX) {
      proc_socket.socket = fields[6];
      proc_socket.family = family;
      proc_socket.protocol = std::atoll(fields[2].data());
      proc_socket.local_port = proc_socket.remote_port = 0U;
      proc_socket.unix_socket_path = (fields.size() >= 8) ? fields[7] : "";
    } else {
      // Two of the fields are the local/remote address/port pairs.
      auto locals = osquery::split(fields[1], ":");
      auto remotes = osquery::split(fields[2], ":");

      if (locals.size() != 2 || remotes.size() != 2) {
        VLOG(1) << "Invalid socket descriptor found: '" << line
                << "'. Skipping this entry";

        continue;
      }

      proc_socket.socket = fields[9];
      proc_socket.family = family;
      proc_socket.protocol = protocol;
      proc_socket.local_address = procDecodeAddressFromHex(locals[0], family);
      proc_socket.local_port = procDecodePortFromHex(locals[1]);
      proc_socket.remote_address = procDecodeAddressFromHex(remotes[0], family);
      proc_socket.remote_port = procDecodePortFromHex(remotes[1]);

      if (proc_socket.protocol == IPPROTO_TCP) {
        char* null_terminator_ptr = nullptr;
        auto integer_socket_state =
            std::strtoull(fields[3].data(), &null_terminator_ptr, 16);
        if (integer_socket_state == 0 ||
            integer_socket_state >= tcp_states.size() ||
            null_terminator_ptr == nullptr || *null_terminator_ptr != 0) {
          proc_socket.state = "UNKNOWN";
        } else {
          proc_socket.state = tcp_states[integer_socket_state];
        }
      }
    }

    // If this socket has no fd, then it means that it is not owned by
    // this process
    auto it = inode_to_fd_map.find(proc_socket.socket);
    if (it == inode_to_fd_map.end()) {
      continue;
    }

    proc_socket.fd = std::atoll(it->second.data());
    if (!callback(proc_socket, user_data)) {
      break;
    }
  }

  return Status(0, "OK");
}
} // namespace osquery
