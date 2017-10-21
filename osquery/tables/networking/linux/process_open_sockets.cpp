/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <arpa/inet.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

// Linux proc protocol define to net stats file name.
const std::map<int, std::string> kLinuxProtocolNames = {
    {IPPROTO_ICMP, "icmp"},
    {IPPROTO_TCP, "tcp"},
    {IPPROTO_UDP, "udp"},
    {IPPROTO_UDPLITE, "udplite"},
    {IPPROTO_RAW, "raw"},
};

std::string addressFromHex(const std::string &encoded_address, int family) {
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
             (unsigned int *)&(decoded.s6_addr[0]),
             (unsigned int *)&(decoded.s6_addr[4]),
             (unsigned int *)&(decoded.s6_addr[8]),
             (unsigned int *)&(decoded.s6_addr[12]));
      inet_ntop(AF_INET6, &decoded, addr_buffer, INET6_ADDRSTRLEN);
    }
  }

  return std::string(addr_buffer);
}

unsigned short portFromHex(const std::string &encoded_port) {
  unsigned short decoded = 0;
  if (encoded_port.length() == 4) {
    sscanf(encoded_port.c_str(), "%hX", &decoded);
  }
  return decoded;
}

void genSocketsFromProc(const InodeMap &inodes,
                        int protocol,
                        int family,
                        QueryData &results) {
  std::string path = "/proc/net/";
  if (family == AF_UNIX) {
    path += "unix";
  } else {
    path += kLinuxProtocolNames.at(protocol);
    path += (family == AF_INET6) ? "6" : "";
  }

  std::string content;
  if (!osquery::readFile(path, content).ok()) {
    // Could not open socket information from /proc.
    return;
  }

  // The system's socket information is tokenized by line.
  size_t index = 0;
  for (const auto &line : osquery::split(content, "\n")) {
    if (++index == 1) {
      // The first line is a textual header and will be ignored.
      if (line.find("sl") != 0 && line.find("sk") != 0 &&
          line.find("Num") != 0) {
        // Header fields are unknown, stop parsing.
        break;
      }
      continue;
    }

    // The socket information is tokenized by spaces, each a field.
    auto fields = osquery::split(line, " ");
    // UNIX socket reporting has a smaller number of fields.
    size_t min_fields = (family == AF_UNIX) ? 7 : 10;
    if (fields.size() < min_fields) {
      // Unknown/malformed socket information.
      continue;
    }

    Row r;
    if (family == AF_UNIX) {
      r["socket"] = fields[6];
      r["family"] = "0";
      r["protocol"] = fields[2];
      r["local_address"] = "";
      r["local_port"] = "0";
      r["remote_address"] = "";
      r["remote_port"] = "0";
      r["path"] = (fields.size() >= 8) ? fields[7] : "";
    } else {
      // Two of the fields are the local/remote address/port pairs.
      auto locals = osquery::split(fields[1], ":");
      auto remotes = osquery::split(fields[2], ":");
      if (locals.size() != 2 || remotes.size() != 2) {
        // Unknown/malformed socket information.
        continue;
      }

      r["socket"] = fields[9];
      r["family"] = INTEGER(family);
      r["protocol"] = INTEGER(protocol);
      r["local_address"] = addressFromHex(locals[0], family);
      r["local_port"] = INTEGER(portFromHex(locals[1]));
      r["remote_address"] = addressFromHex(remotes[0], family);
      r["remote_port"] = INTEGER(portFromHex(remotes[1]));
      // Path is only used for UNIX domain sockets.
      r["path"] = "";
    }

    if (inodes.count(r["socket"]) > 0) {
      r["pid"] = inodes.at(r["socket"]).second;
      r["fd"] = inodes.at(r["socket"]).first;
    } else {
      r["pid"] = "-1";
      r["fd"] = "-1";
    }

    results.push_back(r);
  }
}

QueryData genOpenSockets(QueryContext &context) {
  QueryData results;

  // If a pid is given then set that as the only item in processes.
  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  // Generate a map of socket inode to process tid.
  InodeMap socket_inodes;
  for (const auto &process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      for (const auto &fd : descriptors) {
        if (fd.second.find("socket:[") == 0) {
          // See #792: std::regex is incomplete until GCC 4.9 (skip 8 chars)
          auto inode = fd.second.substr(8);
          socket_inodes[inode.substr(0, inode.size() - 1)] =
              std::make_pair(fd.first, process);
        }
      }
    }
  }

  // This used to use netlink (Ref: #1094) to request socket information.
  // Use proc messages to query socket information.
  for (const auto &protocol : kLinuxProtocolNames) {
    genSocketsFromProc(socket_inodes, protocol.first, AF_INET, results);
    genSocketsFromProc(socket_inodes, protocol.first, AF_INET6, results);
  }

  genSocketsFromProc(socket_inodes, IPPROTO_IP, AF_UNIX, results);
  return results;
}
}
}
