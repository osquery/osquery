/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <unordered_map>

#include <arpa/inet.h>
#include <linux/limits.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
const std::string kLinuxProcPath = "/proc";

struct SocketInfo final {
  std::string socket;
  ino_t net_ns;

  int family{0};
  int protocol{0};

  std::string local_address;
  std::uint16_t local_port{0U};

  std::string remote_address;
  std::uint16_t remote_port{0U};

  std::string unix_socket_path;

  std::string state;
};
typedef std::vector<SocketInfo> SocketInfoList;

struct SocketProcessInfo final {
  std::string pid;
  std::string fd;
};
typedef std::map<std::string, SocketProcessInfo> SocketInodeToProcessInfoMap;

// Linux proc protocol define to net stats file name.
const std::map<int, std::string> kLinuxProtocolNames = {
    {IPPROTO_ICMP, "icmp"},
    {IPPROTO_TCP, "tcp"},
    {IPPROTO_UDP, "udp"},
    {IPPROTO_UDPLITE, "udplite"},
    {IPPROTO_RAW, "raw"},
};

const std::string kPacketPathSuffix{"packet"};

// For sockets without state (eg. raw sockets).
const std::string kSocketStateNone{"NONE"};

// Index of protocol number in /proc/net/packet file.
const std::size_t kPacketLineProtocolIndex{3U};

// Index of inode number in /proc/net/packet file.
const std::size_t kPacketLineInodeIndex{8U};

const std::vector<std::string> tcp_states = {"UNKNOWN",
                                             "ESTABLISHED",
                                             "SYN_SENT",
                                             "SYN_RECV",
                                             "FIN_WAIT1",
                                             "FIN_WAIT2",
                                             "TIME_WAIT",
                                             "CLOSED",
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

/// From an hex encoded address and its socket family, read from
/// a /proc/net file, decode the address and return a string.
///
/// @param encoded_address The encoded address as a string.
/// @param int The family to use to decode address (AF_INET, AF_INET6).
std::string procDecodeAddressFromHex(const std::string& encoded_address,
                                     int family);

/// From an encoded unsigned short (host port, protocol), decode it and
/// return it as an unsigned short
///
/// @param encoded_port The encoded port as a string.
unsigned short procDecodeUnsignedShortFromHex(const std::string& encoded_port);

/// Parse the contents issued from a /proc/net/packet file and fill the socket
/// info list structure.
///
/// @param family The family to set in the SocketInfo entry.
/// @param protocol The protocol entries to result; If 0, return all.
/// @param net_ns The network namespace to set in the SocketInfo entry.
/// @param content The /proc/net/packet content to parse.
/// @param result The SocketInfo list structure to fill with the parsed results.
Status procGetSocketListPacket(int family,
                               int protocol,
                               ino_t net_ns,
                               const std::string& content,
                               SocketInfoList& result);

/// This function parses the inode value in the destination of a user namespace
/// symlink; fail if the namespace name is now what we expect
Status procGetNamespaceInode(ino_t& inode,
                             const std::string& namespace_name,
                             const std::string& process_namespace_root);

std::string procDecodeAddressFromHex(const std::string& encoded_address,
                                     int family);

unsigned short procDecodePortFromHex(const std::string& encoded_port);

/**
 * @brief Construct a map of socket inode number to socket information collected
 * from /proc/<pid>/net for a certain family and protocol under a certain pid.
 *
 * The output parameter result is used as-is, i.e. it IS NOT cleared beforehand,
 * so values will either be added or replace existing ones without check.
 *
 * @param family The socket family. One of AF_INET, AF_INET6 or AF_UNIX.
 * @param protocol The socket protocol. For AF_INET and AF_INET6 one of the keys
 * @param pid Query data for this pid.
 * of kLinuxProtocolNames. For AF_UNIX only IPPROTO_IP is valid.
 * @param result The output parameter.
 */
Status procGetSocketList(int family,
                         int protocol,
                         ino_t net_ns,
                         const std::string& pid,
                         SocketInfoList& result);

/**
 * @brief Construct a map of socket inode number to process information for the
 * process that owns the socket by reading entries under /proc/<pid>/fd.
 *
 * The output parameter result is used as-is, i.e. it IS NOT cleared beforehand,
 * so values will either be added or replace existing ones without check.
 *
 * @param pid The process of interests
 * @param result The output parameter.
 */
Status procGetSocketInodeToProcessInfoMap(const std::string& pid,
                                          SocketInodeToProcessInfoMap& result);

/**
 * @brief Enumerate all pids in the system by listing pid numbers under /proc
 * and execute a callback for each one of them. The callback will receive the
 * pid and the user_data provided as argument.
 *
 * Notice there isn't any type of locking here so race conditions might occur,
 * e.g. a process is destroyed right before the callback being called.
 *
 * The loop will stop after the first callback failed, i.e. returned false.
 *
 * @param user_data User provided data to be passed to the callback
 * @param callback A pointer to the callback function
 */
template <typename UserData>
Status procEnumerateProcesses(UserData& user_data,
                              bool (*callback)(const std::string&, UserData&)) {
  boost::filesystem::directory_iterator it(kLinuxProcPath), end;

  // Some hardening schemes grant only partial permission to
  // /proc. Because of that, we want to keep iterating even if we get
  // a failure. Track if we've gotten any success, and return based on
  // that instead of from an individual iteration. (This does mean
  // that if you have no permissions, you may get a bunch of verbose
  // logs saying so. See https://github.com/osquery/osquery/issues/5709
  bool anySuccess = false;

  for (; it != end; ++it) {
    try {
      if (!boost::filesystem::is_directory(it->status())) {
        continue;
      }

      // See #792: std::regex is incomplete until GCC 4.9
      const auto pid = it->path().leaf().string();
      if (std::atoll(pid.data()) <= 0) {
        continue;
      }

      bool ret = callback(pid, user_data);
      if (ret == false) {
        break;
      }

      anySuccess = true;
    } catch (const boost::filesystem::filesystem_error& e) {
      VLOG(1) << "Exception enumerating /proc: " << e.what();
    }
  }

  if (!anySuccess) {
    return Status::failure("Unsuccessful enumerating /proc");
  }

  return Status(0);
}

/**
 * @brief Enumerate all file descriptors of a certain process identified by its
 * pid by listing files under /proc/<pid>/fd and execute a callback for each one
 * of them. The callback will receive the pid the file descriptor and the real
 * path the file descriptor links to, and the user_data provided as argument.
 *
 * Notice there isn't any type of locking here so race conditions might occur,
 * e.g. a socket is closed right before the callback being called.
 *
 * The loop will stop after the first callback failed, i.e. returned false.
 *
 * @param pid The process id of interest
 * @param user_data User provided data to be passed to the callback
 * @param callback A pointer to the callback function
 */
template <typename UserData>
Status procEnumerateProcessDescriptors(const std::string& pid,
                                       UserData& user_data,
                                       bool (*callback)(const std::string& pid,
                                                        const std::string& fd,
                                                        const std::string& link,
                                                        UserData& user_data)) {
  std::string descriptors_path = kLinuxProcPath + "/" + pid + "/fd";

  try {
    boost::filesystem::directory_iterator it(descriptors_path), end;

    for (; it != end; ++it) {
      auto fd = it->path().leaf().string();

      std::string link;
      Status status = procReadDescriptor(pid, fd, link);
      if (!status.ok()) {
        // Likely because the file descriptor was closed before readlink.
        VLOG(1) << status.getMessage();
        continue;
      }

      bool ret = callback(pid, fd, link, user_data);
      if (ret == false) {
        break;
      }
    }
  } catch (boost::filesystem::filesystem_error& e) {
    VLOG(1) << "Exception iterating process file descriptors: " << e.what();
    return Status::failure(e.what());
  }

  return Status(0);
}

} // namespace osquery
