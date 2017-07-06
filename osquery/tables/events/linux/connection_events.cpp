/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <vector>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/conntrack.h"
#include "osquery/tables/networking/utils.h"

namespace osquery {

/**
 * @brief Track status of network connections
 *
 * This subscriber retrieves events from the ConntrackEventPublisher about
 * status changes
 * of network flows. Flows are defined by source and destination among the
 * ISO/OSI layer 3 and 4.
 */
class ConnectionEventSubscriber
    : public EventSubscriber<ConntrackEventPublisher> {
 public:
  Status init() override;

  /// Nothing to configure
  void configure() override{};

  /**
   * @brief This exports a single Callback for ConntrackEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the ConntrackEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const ECRef& ec, const SCRef& sc);
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers ConnectionEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(ConnectionEventSubscriber, "event_subscriber", "connection_events");

Status ConnectionEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  subscribe(&ConnectionEventSubscriber::Callback, sc);

  return Status(0);
}

void printSockAddress(const sockaddr_storage& addr) {
  char straddr[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
  switch (addr.ss_family) {
    case AF_INET: {
      LOG(INFO) << inet_ntop(AF_INET, &((struct sockaddr_in*)&addr)->sin_addr, straddr, sizeof(straddr)) << ":" << ntohs(((struct sockaddr_in*)&addr)->sin_port);
    }
      break;
    case AF_INET6: {
      LOG(INFO) << inet_ntop(AF_INET, &((struct sockaddr_in6*)&addr)->sin6_addr, straddr, sizeof(straddr)) << ":" << ntohs(((struct sockaddr_in6*)&addr)->sin6_port);
    }
      break;
  }

  LOG(INFO) << inet_ntop(AF_INET, &((struct sockaddr_in*)&addr)->sin_addr, straddr, sizeof(straddr)) << ":" << ntohs(((struct sockaddr_in*)&addr)->sin_port);
}

void printSockAddressTuple(const sockaddr_storage& from_addr, const sockaddr_storage& to_addr) {
  char from_straddr[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
  std::string from_strport;
  switch (from_addr.ss_family) {
    case AF_INET: {
      inet_ntop(AF_INET, &((struct sockaddr_in*)&from_addr)->sin_addr, from_straddr, sizeof(from_straddr));
      from_strport = std::to_string(ntohs(((struct sockaddr_in*)&from_addr)->sin_port));
    }
      break;
    case AF_INET6: {
      inet_ntop(AF_INET, &((struct sockaddr_in6*)&from_addr)->sin6_addr, from_straddr, sizeof(from_straddr));
      from_strport = std::to_string(ntohs(((struct sockaddr_in6*)&from_addr)->sin6_port));
    }
      break;
  }

  char to_straddr[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
  std::string to_strport;
  switch (from_addr.ss_family) {
    case AF_INET: {
      inet_ntop(AF_INET, &((struct sockaddr_in*)&to_addr)->sin_addr, to_straddr, sizeof(to_straddr));
      to_strport = std::to_string(ntohs(((struct sockaddr_in*)&to_addr)->sin_port));
    }
      break;
    case AF_INET6: {
      inet_ntop(AF_INET, &((struct sockaddr_in6*)&to_addr)->sin6_addr, to_straddr, sizeof(to_straddr));
      to_strport = std::to_string(ntohs(((struct sockaddr_in6*)&to_addr)->sin6_port));
    }
      break;
  }

  LOG(INFO) << "(" << from_straddr << ":" << from_strport << " -> " << to_straddr << ":" << to_strport << ")";
}

void printConnection(Row r) {
  LOG(INFO) << "(" << r["orig_address"] << ":" << r["orig_port"] << " -> " << r["resp_address"] << ":" << r["resp_port"] << ")";
}

unsigned short getPortFromSockAddr(const sockaddr_storage& addr) {
  switch (addr.ss_family) {
    case AF_INET: {
       return ntohs(((struct sockaddr_in*)&addr)->sin_port);
    }
    case AF_INET6: {
      return ntohs(((struct sockaddr_in6*)&addr)->sin6_port);
    }
  }

  return 0;
}

inline void setConntrackMsgType(Row& r, const ConntrackEventContextRef& ec) {
  switch (ec->type) {
    case NFCT_T_NEW:
      r["type"] = "NEW";
      break;
    case NFCT_T_UPDATE:
      r["type"] = "UPDATE";
      break;
    case NFCT_T_DESTROY:
      r["type"] = "DESTROY";
      break;
    default:
      r["type"] = "";
      LOG(WARNING) << "Unexpected conntrack message type" << ec->type;
  }
}

inline void setLayer4(Row& r, sockaddr_storage& orig_addr, sockaddr_storage& resp_addr, const ConntrackEventContextRef& ec) {
  struct nfct_attr_grp_port ports;
  nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_PORT, &ports);
  unsigned short orig_port_src = ntohs(ports.sport);
  unsigned short orig_port_dst = ntohs(ports.dport);

  switch (orig_addr.ss_family) {
    case AF_INET: {
      ((struct sockaddr_in *) &orig_addr)->sin_port = ports.sport;
      ((struct sockaddr_in *) &resp_addr)->sin_port = ports.dport;
    }
      break;
    case AF_INET6: {
      ((struct sockaddr_in6 *) &orig_addr)->sin6_port = ports.sport;
      ((struct sockaddr_in6 *) &resp_addr)->sin6_port = ports.dport;
    }
      break;
    default:
      LOG(ERROR) << "Unkown L3 Protocol when casting sockaddr_storage";
  }

  r["orig_port"] = INTEGER(orig_port_src);
  r["resp_port"] = INTEGER(orig_port_dst);
  r["protocol"] =
          INTEGER((int)nfct_get_attr_u8(ec->event.get(), ATTR_ORIG_L4PROTO));
}

inline void setLayer3IPv4(Row& r, sockaddr_storage& src_addr, sockaddr_storage& dst_addr, const ConntrackEventContextRef& ec) {
  struct nfct_attr_grp_ipv4 ipv4;
  nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_IPV4, &ipv4);
  ((struct sockaddr_in*)&src_addr)->sin_addr.s_addr = ipv4.src;
  ((struct sockaddr_in*)&dst_addr)->sin_addr.s_addr = ipv4.dst;

  r["orig_address"] =
          std::string{inet_ntoa(((struct sockaddr_in*)&src_addr)->sin_addr)};
  r["resp_address"] =
          std::string{inet_ntoa(((struct sockaddr_in*)&dst_addr)->sin_addr)};
}

inline void setLayer3IPv6(Row& r, sockaddr_storage& src_addr, sockaddr_storage& dst_addr, const ConntrackEventContextRef& ec) {
  struct nfct_attr_grp_ipv6 ipv6;
  nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_IPV6, &ipv6);
  memcpy(&((struct sockaddr_in6*)&src_addr)->sin6_addr,
         &ipv6.src,
         sizeof(ipv6.src));
  memcpy(&((struct sockaddr_in6*)&dst_addr)->sin6_addr,
         &ipv6.dst,
         sizeof(ipv6.dst));

  char straddr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6,
            &((struct sockaddr_in6*)&src_addr)->sin6_addr,
            straddr,
            sizeof(straddr));
  r["orig_address"] = std::string{straddr};
  inet_ntop(AF_INET6,
            &((struct sockaddr_in6*)&dst_addr)->sin6_addr,
            straddr,
            sizeof(straddr));
  r["resp_address"] = std::string{straddr};
}

int sendNLDiagMessage(int sockfd, int protocol, int family, const sockaddr_storage& local_addr) {
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
            ~((1 << tables::TCP_SYN_RECV) | (1 << tables::TCP_TIME_WAIT) | (1 << tables::TCP_CLOSE));
    // Request additional TCP information.
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
  } else {
    conn_req.idiag_states = -1;
  }

  if(family != local_addr.ss_family) {
    LOG(ERROR) << "Given family does not correspond to ss_family";
  }
  switch (family) {
    case AF_INET: {
      *((struct in_addr*)&conn_req.id.idiag_src) = ((struct sockaddr_in*)&local_addr)->sin_addr;
      conn_req.id.idiag_sport = ((struct sockaddr_in*)&local_addr)->sin_port;
    }
      break;
    case AF_INET6: {
      memcpy(&((struct sockaddr_in6*)&conn_req.id.idiag_src)->sin6_addr,
             &((struct sockaddr_in6*)&local_addr)->sin6_addr, sizeof(((struct sockaddr_in6*)&local_addr)->sin6_addr));
      conn_req.id.idiag_sport = ((struct sockaddr_in6*)&local_addr)->sin6_port;
    }
      break;
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
  row["user"] = BIGINT(diag_msg->idiag_uid);
  row["family"] = INTEGER(family);
  row["protocol"] = INTEGER(protocol);
  row["local_address"] = TEXT(local_addr_buf);
  row["remote_address"] = TEXT(remote_addr_buf);
  row["local_port"] = INTEGER(ntohs(diag_msg->id.idiag_sport));
  row["remote_port"] = INTEGER(ntohs(diag_msg->id.idiag_dport));
  return row;
}

Status getSocketForConnection(int protocol, const sockaddr_storage& local_addr, Row& row) {
  // set up the socket
  int nl_sock = 0;
  if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
    return Status(1, "Could not create netlink socket");
  }

  // send the inet_diag message
  if (sendNLDiagMessage(nl_sock, protocol, local_addr.ss_family, local_addr) < 0) {
    close(nl_sock);
    return Status(1, "Could not send netlink message");
  }

  // recieve netlink messages
  uint8_t recv_buf[SOCKET_BUFFER_SIZE];
  int numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
  if (numbytes <= 0) {
    close(nl_sock);
    return Status(1, "NETLINK receive failed");
  }

  QueryData results;
  auto nlh = (struct nlmsghdr *)recv_buf;
  while (NLMSG_OK(nlh, numbytes)) {
    if (nlh->nlmsg_type == NLMSG_DONE) {
      break;
    }

    // NOTICE: This would return errors (invalid parameters on CentOS/RHEL6).
    if (nlh->nlmsg_type == NLMSG_ERROR) {
      LOG(WARNING) << "NLMSG_ERROR when processing NETLINK response";
      close(nl_sock);
      return Status(1, "Could not read netlink response");
    }

    // parse and process netlink message
    auto diag_msg = (struct inet_diag_msg *)NLMSG_DATA(nlh);
    auto r = getNLDiagMessage(diag_msg, protocol, local_addr.ss_family);
    results.push_back(r);


    /*
    if (socket_inodes.count(row["socket"]) > 0) {
      row["pid"] = socket_inodes.at(row["socket"]);
    } else {
      row["pid"] = "-1";
    }

    results.push_back(row);
    */
    nlh = NLMSG_NEXT(nlh, numbytes);
  }

  if(results.size() > 1) {
    LOG(ERROR) << "Expected at most one connection/socket bound to local IP:Port combination";
    close(nl_sock);
    return Status(1, "Ambiguous socket results for specific connection");
  }

  if ( results.size() > 0 ) {
    if (results.at(0).count("socket") >= 1 && !results.at(0)["socket"].empty()) {
      row["socket"] = results.at(0)["socket"];
    }
    if (results.at(0).count("user") >= 1 && !results.at(0)["user"].empty()) {
      row["user"] = results.at(0)["user"];
    }
  }

  close(nl_sock);
  return Status(0, "OK");
}

Status ConnectionEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  if (ec->type != NFCT_T_NEW) {
    return Status(0, "OK");
  }

  struct sockaddr_storage orig_addr, resp_addr;
  Row r;

  // Conntrack message type
  setConntrackMsgType(r, ec);

  orig_addr.ss_family = nfct_get_attr_u8(ec->event.get(), ATTR_ORIG_L3PROTO);
  resp_addr.ss_family = orig_addr.ss_family;

  // Layer 4 - UDP and TCP (protocol and port numbers)
  setLayer4(r, orig_addr, resp_addr, ec);

  // Layer 3 (AF) - IPv4 and IPv6
  switch (orig_addr.ss_family) {
  case AF_INET: {
    setLayer3IPv4(r, orig_addr, resp_addr, ec);
  } break;
  case AF_INET6: {
    setLayer3IPv6(r, orig_addr, resp_addr, ec);
  } break;
  default: {
    LOG(WARNING) << "Unsupported level 3 protocol number: " +
                    std::to_string(orig_addr.ss_family);
    add(r);
    return Status(0, "Unsupported level 3 protocol number");
  }
  }

  // Others
  std::set<std::string> pids;
  procProcesses(pids);
  r["time"] = "";
  r["uid"] = "";
  r["inode"] = "";
  r["fd"] = "";
  r["pid"] = "";

  // Ask socket_diag for more information
  // TODO: Broadcast addresses does not seems to match (/proc <-> conntrack)
  Row socket_row;
  LOG(INFO) << "";
  LOG(INFO) << "Searching socket for connection:";
  printConnection(r);

  if (getPortFromSockAddr(orig_addr) == 0) {
    LOG(WARNING) << "Skip orig_addr because port is zero";
  } else {
    LOG(INFO) << "Trying to find local socket with orig_addr";
    getSocketForConnection(std::stoi(r["protocol"]), orig_addr, socket_row);
  }

  if (getPortFromSockAddr(resp_addr) == 0) {
    LOG(WARNING) << "Skip resp_addr because port is zero";
  } else {
    if (socket_row.count("socket") == 0 && socket_row.count("user") == 0 ) {
      LOG(INFO) << "Trying to find local socket with resp_addr";
      getSocketForConnection(std::stoi(r["protocol"]), resp_addr, socket_row);
    }
  }

  // Did we find the socket and process?
  if (socket_row.count("socket") == 0 && socket_row.count("user") == 0) {
    LOG(WARNING) << "Did not find socket or user";
    add(r);
    return Status(0, "No socket or user for connection found");
  }
  r["inode"] = socket_row["socket"];
  r["uid"] = socket_row["user"];
  
  // Find the process to the respective inode - Search among the entries in
  // /proc/<pid>/fd
  tables::InodeMap inodes;
  std::pair<std::string, std::string> fd_n_process;
  for (const auto& process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      for (const auto& fd : descriptors) {
        if (fd.second.find("socket:[") == 0) {
          // See #792: std::regex is incomplete until GCC 4.9 (skip 8 chars)
          auto inode = fd.second.substr(8, fd.second.size() - 8 - 1);
          if (inode == r["inode"]) {
            // Process found
            if (!fd_n_process.first.empty() || !fd_n_process.second.empty()) {
              LOG(ERROR) << "Ambiguous process information found for socket";
            }
            fd_n_process = std::make_pair(fd.first, process);
          }
        }
      }
    }
  }

  if (fd_n_process.second.empty()) {
    add(r);
    return Status(0, "No process for inode found");
  }
  r["fd"] = fd_n_process.first;
  r["pid"] = fd_n_process.second;

  // A callback is somewhat useless unless it changes the EventSubscriber
  // state or calls `add` to store a marked up event.
  add(r);

  return Status(0, "OK");
}
}
