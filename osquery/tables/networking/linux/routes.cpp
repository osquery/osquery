// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>

#include <stdlib.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <boost/algorithm/string/trim.hpp>

#include <glog/logging.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

#define MAX_NETLINK_SIZE 8192

std::string getNetlinkIP(int family, const char* buffer) {
  char dst[INET6_ADDRSTRLEN];
  memset(dst, 0, INET6_ADDRSTRLEN);

  inet_ntop(family, buffer, dst, INET6_ADDRSTRLEN);
  std::string address(dst);
  boost::trim(address);

  return address;
}

Status readNetlink(int socket_fd, int seq, char* output, size_t* size) {
  struct nlmsghdr* nl_hdr;

  size_t message_size = 0;
  do {
    int bytes = 0;
    while (bytes == 0) {
      bytes = recv(socket_fd, output, MAX_NETLINK_SIZE - message_size, 0);
      if (bytes < 0) {
        return Status(1, "Could not read from NETLINK.");
      }
    }

    // Assure valid header response, and not an error type.
    nl_hdr = (struct nlmsghdr*)output;
    if (NLMSG_OK(nl_hdr, bytes) == 0 || nl_hdr->nlmsg_type == NLMSG_ERROR) {
      return Status(1, "Read invalid NETLINK message.");
    }

    if (nl_hdr->nlmsg_type == NLMSG_DONE) {
      break;
    }

    // Move the buffer pointer
    output += bytes;
    message_size += bytes;
    if ((nl_hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
      break;
    }
  } while (nl_hdr->nlmsg_seq != seq || nl_hdr->nlmsg_pid != getpid());

  *size = message_size;
  return Status(0, "OK");
}

void genNetlinkRoutes(const struct nlmsghdr* netlink_msg, QueryData& results) {
  std::string address;
  int mask = 0;
  char interface[IF_NAMESIZE];

  struct rtmsg* message = (struct rtmsg*)NLMSG_DATA(netlink_msg);
  struct rtattr* attr = (struct rtattr*)RTM_RTA(message);
  int attr_size = RTM_PAYLOAD(netlink_msg);

  Row r;

  // Iterate over each route in the netlink message
  bool has_destination = false;
  r["metric"] = "0";
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
    }
    attr = RTA_NEXT(attr, attr_size);
  }

  if (!has_destination) {
    r["destination"] = "0.0.0.0";
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

  // Fields not supported by Linux routes:
  r["mtu"] = "0";
  results.push_back(r);
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;

  int socket_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (socket_fd < 0) {
    LOG(ERROR) << "Cannot open NETLINK socket.";
    return results;
  }

  // Create netlink message header
  void* netlink_buffer = malloc(MAX_NETLINK_SIZE);
  struct nlmsghdr* netlink_msg = (struct nlmsghdr*)netlink_buffer;
  if (netlink_msg == nullptr) {
    close(socket_fd);
    return results;
  }

  netlink_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  netlink_msg->nlmsg_type = RTM_GETROUTE; // routes from kernel routing table
  netlink_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  netlink_msg->nlmsg_seq = 0;
  netlink_msg->nlmsg_pid = getpid();

  // Send the netlink request to the kernel
  if (send(socket_fd, netlink_msg, netlink_msg->nlmsg_len, 0) < 0) {
    LOG(ERROR) << "Cannot write NETLINK request header to socket.";
    goto cleanup;
  }

  // Wrap the read socket to support multi-netlink messages
  size_t size;
  if (!readNetlink(socket_fd, 1, (char*)netlink_msg, &size).ok()) {
    LOG(ERROR) << "Cannot read NETLINK response from socket.";
    goto cleanup;
  }

  // Treat the netlink response as route information
  while (NLMSG_OK(netlink_msg, size)) {
    genNetlinkRoutes(netlink_msg, results);
    netlink_msg = NLMSG_NEXT(netlink_msg, size);
  }

cleanup:
  close(socket_fd);
  free(netlink_buffer);

  return results;
}
}
}
