/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

#define MAX_NETLINK_SIZE 8192
#define MAX_NETLINK_ATTEMPTS 8

constexpr auto kDefaultIpv6Route = "::";
constexpr auto kDefaultIpv4Route = "0.0.0.0";

std::string getNetlinkIP(int family, const char* buffer) {
  char dst[INET6_ADDRSTRLEN] = {0};

  if (inet_ntop(family, buffer, dst, INET6_ADDRSTRLEN) == nullptr) {
    LOG(ERROR) << "Unsupported address family: " << family;
    return "";
  }
  std::string address(dst);
  boost::trim(address);

  return address;
}

std::string getDefaultRouteIP(int family) {
  switch (family) {
  case AF_INET:
    return kDefaultIpv4Route;
  case AF_INET6:
    return kDefaultIpv6Route;
  default:
    LOG(ERROR) << "Unsupported address family: " << family;
    return "";
  }
}

void genNetlinkRoutes(const struct nlmsghdr* netlink_msg, QueryData& results) {
  std::string address;
  int mask = 0;
  char interface[IF_NAMESIZE] = {0};

  struct rtmsg* message = static_cast<struct rtmsg*>(NLMSG_DATA(netlink_msg));
  struct rtattr* attr = static_cast<struct rtattr*>(RTM_RTA(message));
  uint32_t attr_size = RTM_PAYLOAD(netlink_msg);

  Row r;

  // Iterate over each route in the netlink message
  bool has_destination = false;
  r["metric"] = "0";
  r["hopcount"] = INTEGER(0);
  r["mtu"] = INTEGER(0);
  while (RTA_OK(attr, attr_size)) {
    switch (attr->rta_type) {
    case RTA_OIF:
      if_indextoname(*(int*)RTA_DATA(attr), interface);
      r["interface"] = std::string(interface);
      break;
    case RTA_GATEWAY:
      address = getNetlinkIP(message->rtm_family, (char*)RTA_DATA(attr));
      r["gateway"] = address;
      break;
    case RTA_PREFSRC:
      address = getNetlinkIP(message->rtm_family, (char*)RTA_DATA(attr));
      r["source"] = address;
      break;
    case RTA_DST:
      if (message->rtm_dst_len != 32 && message->rtm_dst_len != 128) {
        mask = (int)message->rtm_dst_len;
      }
      address = getNetlinkIP(message->rtm_family, (char*)RTA_DATA(attr));
      r["destination"] = address;
      has_destination = true;
      break;
    case RTA_PRIORITY:
      r["metric"] = INTEGER(*(int*)RTA_DATA(attr));
      break;
    case RTA_METRICS:
      struct rtattr* xattr = static_cast<struct rtattr*> RTA_DATA(attr);
      auto xattr_size = RTA_PAYLOAD(attr);
      while (RTA_OK(xattr, xattr_size)) {
        switch (xattr->rta_type) {
        case RTAX_MTU:
          r["mtu"] = INTEGER(*reinterpret_cast<int*>(RTA_DATA(xattr)));
          break;
        case RTAX_HOPLIMIT:
          r["hopcount"] = INTEGER(*reinterpret_cast<int*>(RTA_DATA(xattr)));
          break;
        }
        xattr = RTA_NEXT(xattr, xattr_size);
      }
      break;
    }
    attr = RTA_NEXT(attr, attr_size);
  }

  if (!has_destination) {
    r["destination"] = getDefaultRouteIP(message->rtm_family);
    if (message->rtm_dst_len) {
      mask = (int)message->rtm_dst_len;
    }
  }

  // Route type determination
  if (message->rtm_type == RTN_UNICAST) {
    r["type"] = "gateway";
  } else if (message->rtm_type == RTN_LOCAL) {
    r["type"] = "local";
  } else if (message->rtm_type == RTN_BROADCAST) {
    r["type"] = "broadcast";
  } else if (message->rtm_type == RTN_ANYCAST) {
    r["type"] = "anycast";
  } else {
    r["type"] = "other";
  }

  r["flags"] = INTEGER(message->rtm_flags);

  // This is the cidr-formatted mask
  r["netmask"] = INTEGER(mask);

  results.push_back(r);
}

/*
 * Reads from socket until buffer is full or recv() returns -1.
 * Uses non-blocking recv with usleep.
 */
static size_t readNetlinkAll(int socket_fd,
                             int seq,
                             char* dest,
                             size_t destsize) {
  size_t remaining = destsize;
  char* p = dest;

  while (1) {
    ssize_t bytes_read = recv(socket_fd, p, remaining, MSG_DONTWAIT);

    if (bytes_read < 0) {
      break;
    }

    p += bytes_read;
    remaining -= bytes_read;

    if (remaining <= 0) {
      LOG(WARNING) << "buffer full - exiting";
      break;
    }

    ::usleep(20);
  }

  return static_cast<size_t>(p - dest);
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;

  int socket_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (socket_fd < 0) {
    VLOG(1) << "Cannot open NETLINK socket";
    return {};
  }

  // Create netlink message header
  auto netlink_buffer = (void*)malloc(MAX_NETLINK_SIZE);
  if (netlink_buffer == nullptr) {
    close(socket_fd);
    return {};
  }

  memset(netlink_buffer, 0, MAX_NETLINK_SIZE);
  struct nlmsghdr* netlink_msg = (struct nlmsghdr*)netlink_buffer;
  netlink_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  netlink_msg->nlmsg_type = RTM_GETROUTE; // routes from kernel routing table
  netlink_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ATOMIC;
  netlink_msg->nlmsg_seq = 0;
  netlink_msg->nlmsg_pid = getpid();

  // Send the netlink request to the kernel
  if (send(socket_fd, netlink_msg, netlink_msg->nlmsg_len, 0) < 0) {
    TLOG << "Cannot write NETLINK request header to socket";
    close(socket_fd);
    free(netlink_buffer);
    return {};
  }

  size_t size = readNetlinkAll(
      socket_fd, 1, reinterpret_cast<char*>(netlink_msg), MAX_NETLINK_SIZE);

  // Treat the netlink response as route information
  while (NLMSG_OK(netlink_msg, size) &&
         (netlink_msg->nlmsg_type != NLMSG_DONE)) {
    genNetlinkRoutes(netlink_msg, results);
    netlink_msg = NLMSG_NEXT(netlink_msg, size);
  }

  close(socket_fd);
  free(netlink_buffer);
  return results;
}
} // namespace tables
} // namespace osquery
