/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/tables/networking/posix/utils.h>

namespace osquery {
namespace tables {

#define MAX_NETLINK_SIZE 64 * 1024

constexpr auto kDefaultIpv6Route = "::";
constexpr auto kDefaultIpv4Route = "0.0.0.0";
constexpr unsigned kMaxPollWaitInMS{5000}; // MAX poll wait in milliseconds

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

Status readNetlink(int socket_fd, int seq, char* output, size_t* size) {
  struct nlmsghdr* nl_hdr = nullptr;
  pollfd fds[] = {{socket_fd, POLLIN, 0}};
  auto start_time_pt = std::chrono::steady_clock::now();
  do {
    ssize_t bytes = 0;
    while (bytes == 0) {
      auto cur_time_pt = std::chrono::steady_clock::now();
      auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                              cur_time_pt - start_time_pt)
                              .count();
      if (time_elapsed >= kMaxPollWaitInMS) {
        LOG(WARNING) << "Netlink timeout";
        return Status(1, "Netlink timeout");
      }

      int poll_status = ::poll(fds, 1, kMaxPollWaitInMS - time_elapsed);
      if (poll_status == 0) {
        LOG(WARNING) << "Netlink timeout";
        return Status(1, "Netlink timeout");
      } else if (poll_status < 0) {
        if (errno != EINTR) {
          LOG(WARNING) << "poll() failed with error " << errno;
          return Status(1, "poll() failed");
        }
        continue;
      }

      if ((fds[0].revents & POLLIN) == 0) {
        continue;
      }

      if (MAX_NETLINK_SIZE - *size >= sizeof(struct nlmsghdr)) {
        bytes = recv(socket_fd, output, MAX_NETLINK_SIZE - *size, 0);
        if (bytes < 0) {
          // Unrecoverable NETLINK error, bail.
          return Status(1, "Could not read from NETLINK");
        }
      } else {
        break;
      }
    }

    if (bytes == 0 && *size == 0) {
      return Status(1, "No data returned from NETLINK");
    }

    // Assure valid header response, and not an error type.
    nl_hdr = (struct nlmsghdr*)output;
    if (NLMSG_OK(nl_hdr, bytes) == 0 || nl_hdr->nlmsg_type == NLMSG_ERROR) {
      if (*size) {
        return Status(0, "Process whatever we received");
      }
      return Status(1, "Read invalid NETLINK message");
    }

    if (static_cast<pid_t>(nl_hdr->nlmsg_seq) != seq ||
        static_cast<pid_t>(nl_hdr->nlmsg_pid) != getpid()) {
      continue;
    }

    if (nl_hdr->nlmsg_type == NLMSG_DONE) {
      break;
    }

    *size += bytes;
    output += bytes;

    if ((nl_hdr->nlmsg_flags & NLM_F_MULTI)) {
      continue;
    }
  } while (true);

  return Status::success();
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
  auto netlink_msg = (struct nlmsghdr*)netlink_buffer;
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

  // Wrap the read socket to support multi-netlink messages
  size_t size = 0;
  if (!readNetlink(socket_fd, 0, (char*)netlink_msg, &size).ok()) {
    TLOG << "Cannot read NETLINK response from socket";
    close(socket_fd);
    free(netlink_buffer);
    return {};
  }

  // Treat the netlink response as route information
  while (NLMSG_OK(netlink_msg, size)) {
    genNetlinkRoutes(netlink_msg, results);
    netlink_msg = NLMSG_NEXT(netlink_msg, size);
  }

  close(socket_fd);
  free(netlink_buffer);
  return results;
}
}
}
