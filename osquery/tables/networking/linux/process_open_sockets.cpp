/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <arpa/inet.h>
#include <linux/netlink.h>

#include <boost/algorithm/string/split.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

// From uapi/linux/sock_diag.h
// From linux/sock_diag.h (<= 3.6)
#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

#include "inet_diag.h"

namespace osquery {
namespace tables {

// heavily influenced by github.com/kristrev/inet-diag-example
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING
};

#define TCPF_ALL 0xFFF
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int sendNLDiagMessage(int sockfd, int protocol, int family) {
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  // Only interested in network sockets currently.
  struct inet_diag_req_v2 conn_req;
  memset(&conn_req, 0, sizeof(conn_req));
  conn_req.sdiag_family = family;
  conn_req.sdiag_protocol = protocol;
  if (protocol == IPPROTO_TCP) {
    conn_req.idiag_states =
        TCPF_ALL &
        ~((1 << TCP_SYN_RECV) | (1 << TCP_TIME_WAIT) | (1 << TCP_CLOSE));
    // Request additional TCP information.
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
  } else {
    conn_req.idiag_states = -1;
  }

  struct nlmsghdr nlh;
  memset(&nlh, 0, sizeof(nlh));
  nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
  nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

  struct iovec iov[4];
  iov[0].iov_base = (void *)&nlh;
  iov[0].iov_len = sizeof(nlh);
  iov[1].iov_base = (void *)&conn_req;
  iov[1].iov_len = sizeof(conn_req);

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void *)&sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  int retval = sendmsg(sockfd, &msg, 0);
  return retval;
}

Row getNLDiagMessage(const struct inet_diag_msg *diag_msg,
                     int protocol,
                     int family) {
  char local_addr_buf[INET6_ADDRSTRLEN] = {0};
  char remote_addr_buf[INET6_ADDRSTRLEN] = {0};

  // set up data structures depending on idiag_family type
  if (diag_msg->idiag_family == AF_INET) {
    inet_ntop(AF_INET,
              (struct in_addr *)&(diag_msg->id.idiag_src),
              local_addr_buf,
              INET_ADDRSTRLEN);
    inet_ntop(AF_INET,
              (struct in_addr *)&(diag_msg->id.idiag_dst),
              remote_addr_buf,
              INET_ADDRSTRLEN);
  } else if (diag_msg->idiag_family == AF_INET6) {
    inet_ntop(AF_INET6,
              (struct in_addr6 *)&(diag_msg->id.idiag_src),
              local_addr_buf,
              INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6,
              (struct in_addr6 *)&(diag_msg->id.idiag_dst),
              remote_addr_buf,
              INET6_ADDRSTRLEN);
  }

  // populate the Row from diag_msg fields
  Row row;
  row["socket"] = INTEGER(diag_msg->idiag_inode);
  row["family"] = INTEGER(family);
  row["protocol"] = INTEGER(protocol);
  row["local_address"] = TEXT(local_addr_buf);
  row["remote_address"] = TEXT(remote_addr_buf);
  row["local_port"] = INTEGER(ntohs(diag_msg->id.idiag_sport));
  row["remote_port"] = INTEGER(ntohs(diag_msg->id.idiag_dport));
  return row;
}

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

  return TEXT(addr_buffer);
}

unsigned short portFromHex(const std::string &encoded_port) {
  unsigned short decoded = 0;
  if (encoded_port.length() == 4) {
    sscanf(encoded_port.c_str(), "%hX", &decoded);
  }
  return decoded;
}

/// A fallback method for generating socket information from /proc/net
void genSocketsFromProc(const std::map<std::string, std::string> &socket_inodes,
                        int protocol,
                        int family,
                        QueryData &results) {
  std::string path = "/proc/net/";
  path += (protocol == IPPROTO_UDP) ? "udp" : "tcp";
  path += (family == AF_INET6) ? "6" : "";

  std::string content;
  if (!osquery::readFile(path, content).ok()) {
    // Could not open socket information from /proc.
    return;
  }

  // The system's socket information is tokenized by line.
  size_t index = 0;
  for (const auto &line : osquery::split(content, "\n")) {
    index += 1;
    if (index == 1) {
      // The first line is a textual header and will be ignored.
      if (line.find("sl") != 0) {
        // Header fields are unknown, stop parsing.
        break;
      }
      continue;
    }

    // The socket information is tokenized by spaces, each a field.
    auto fields = osquery::split(line, " ");
    if (fields.size() < 10) {
      // Unknown/malformed socket information.
      continue;
    }

    // Two of the fields are the local/remote address/port pairs.
    auto locals = osquery::split(fields[1], ":");
    auto remotes = osquery::split(fields[2], ":");
    if (locals.size() != 2 || remotes.size() != 2) {
      // Unknown/malformed socket information.
      continue;
    }

    Row r;
    r["socket"] = fields[9];
    r["family"] = INTEGER(family);
    r["protocol"] = INTEGER(protocol);
    r["local_address"] = addressFromHex(locals[0], family);
    r["local_port"] = INTEGER(portFromHex(locals[1]));
    r["remote_address"] = addressFromHex(remotes[0], family);
    r["remote_port"] = INTEGER(portFromHex(remotes[1]));

    if (socket_inodes.count(r["socket"]) > 0) {
      r["pid"] = socket_inodes.at(r["socket"]);
    } else {
      r["pid"] = "-1";
    }

    results.push_back(r);
  }
}

void genSocketsForFamily(
    const std::map<std::string, std::string> &socket_inodes,
    int protocol,
    int family,
    QueryData &results) {
  // set up the socket
  int nl_sock = 0;
  if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
    return;
  }

  // send the inet_diag message
  if (sendNLDiagMessage(nl_sock, protocol, family) < 0) {
    close(nl_sock);
    return;
  }

  // recieve netlink messages
  uint8_t recv_buf[SOCKET_BUFFER_SIZE];
  int numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
  if (numbytes <= 0) {
    VLOG(1) << "NETLINK receive failed";
    return;
  }

  auto nlh = (struct nlmsghdr *)recv_buf;
  while (NLMSG_OK(nlh, numbytes)) {
    if (nlh->nlmsg_type == NLMSG_DONE) {
      break;
    }

    if (nlh->nlmsg_type == NLMSG_ERROR) {
      genSocketsFromProc(socket_inodes, protocol, family, results);
      break;
    }

    // parse and process netlink message
    auto diag_msg = (struct inet_diag_msg *)NLMSG_DATA(nlh);
    auto row = getNLDiagMessage(diag_msg, protocol, family);

    if (socket_inodes.count(row["socket"]) > 0) {
      row["pid"] = socket_inodes.at(row["socket"]);
    } else {
      row["pid"] = "-1";
    }

    results.push_back(row);
    nlh = NLMSG_NEXT(nlh, numbytes);
  }

  close(nl_sock);
  return;
}

QueryData genOpenSockets(QueryContext &context) {
  QueryData results;

  // If a pid is given then set that as the only item in processes.
  std::set<std::string> pids;
  if (context.constraints["pid"].exists()) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  // Generate a map of socket inode to process tid.
  std::map<std::string, std::string> socket_inodes;
  for (const auto &process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      for (const auto& fd : descriptors) {
        if (fd.second.find("socket:") != std::string::npos) {
          // See #792: std::regex is incomplete until GCC 4.9
          auto inode = fd.second.substr(fd.second.find("socket:") + 8);
          socket_inodes[inode.substr(0, inode.size() - 1)] = process;
        }
      }
    }
  }

  // Use netlink messages to query socket information.
  genSocketsForFamily(socket_inodes, IPPROTO_TCP, AF_INET, results);
  genSocketsForFamily(socket_inodes, IPPROTO_UDP, AF_INET, results);
  genSocketsForFamily(socket_inodes, IPPROTO_TCP, AF_INET6, results);
  genSocketsForFamily(socket_inodes, IPPROTO_UDP, AF_INET6, results);
  return results;
}
}
}
