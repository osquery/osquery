// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>

#include <stdlib.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/tables/networking/utils.h"

using namespace osquery::db;

namespace osquery {
namespace tables {

#define MAX_NETLINK_SIZE 8192

std::string netlink_ip(int family, const char* buffer) {
  char dst[INET6_ADDRSTRLEN];
  memset(dst, 0, INET6_ADDRSTRLEN);

  inet_ntop(family, buffer, dst, INET6_ADDRSTRLEN);
  std::string address(dst);
  boost::trim(address);

  return address;
}

int read_netlink(int socket_fd, char* output, int seq) {
  struct nlmsghdr* nl_hdr;

  int bytes, message_size;
  do {
    bytes = recv(socket_fd, output, MAX_NETLINK_SIZE - message_size, 0);
    if (bytes < 0) {
      return -1;
    }

    // Assure valid header response, and not an error type.
    nl_hdr = (struct nlmsghdr*)output;
    if (NLMSG_OK(nl_hdr, bytes) == 0 || nl_hdr->nlmsg_type == NLMSG_ERROR) {
      return -1;
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

  return message_size;
}

void genNetlinkRoutes(const struct nlmsghdr* netlink_msg, QueryData& results) {
  struct rtmsg* message;
  struct rtattr* attr;

  std::string address;
  int mask = 0;
  char interface[IF_NAMESIZE];
  bool has_destination;

  int attr_size;

  message = (struct rtmsg*)NLMSG_DATA(netlink_msg);
  attr = (struct rtattr*)RTM_RTA(message);
  attr_size = RTM_PAYLOAD(netlink_msg);

  Row r;

  // Iterate over each route in the netlink message
  has_destination = false;
  while (RTA_OK(attr, attr_size)) {
    switch (attr->rta_type) {
    case RTA_OIF:
      if_indextoname(*(int*)RTA_DATA(attr), interface);
      r["interface"] = std::string(interface);
      break;
    case RTA_GATEWAY:
      address = netlink_ip(message->rtm_family, (char*)RTA_DATA(attr));
      r["gateway"] = address;
      break;
    case RTA_PREFSRC:
      address = netlink_ip(message->rtm_family, (char*)RTA_DATA(attr));
      r["source"] = address;
      break;
    case RTA_DST:
      if (message->rtm_dst_len != 32 && message->rtm_dst_len != 128) {
        mask = (int)message->rtm_dst_len;
      }
      address = netlink_ip(message->rtm_family, (char*)RTA_DATA(attr));
      r["destination"] = address;
      has_destination = true;
      break;
    case RTA_PRIORITY:
      r["metric"] = boost::lexical_cast<std::string>(*(int*)RTA_DATA(attr));
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

  // This is the cidr-formatted mask
  r["genmask"] = boost::lexical_cast<std::string>(mask);

  results.push_back(r);
}

QueryData genRoutes() {
  QueryData results;

  void* netlink_buffer;
  struct nlmsghdr* netlink_msg;

  int socket_fd, size;

  socket_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (socket_fd < 0) {
    LOG(ERROR) << "Cannot open NETLINK socket.";
    return results;
  }

  // Create netlink message header
  netlink_msg = (struct nlmsghdr*)malloc(MAX_NETLINK_SIZE);
  netlink_buffer = (void*)netlink_msg;
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
  size = read_netlink(socket_fd, (char*)netlink_msg, 1);
  if (size < 0) {
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
  if (netlink_buffer != NULL) {
    free(netlink_buffer);
  }

  return results;
}
}
}
