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

Status ConnectionEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  struct sockaddr_storage src_addr, dst_addr;
  Row r;

  // Conntrack message type
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

  // Layer 4 - UDP and TCP
  r["protocol"] =
      INTEGER((int)nfct_get_attr_u8(ec->event.get(), ATTR_ORIG_L4PROTO));
  struct nfct_attr_grp_port ports;
  nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_PORT, &ports);
  unsigned short orig_port_src = ntohs(ports.sport);
  r["orig_port"] = INTEGER(orig_port_src);
  unsigned short orig_port_dst = ntohs(ports.dport);
  r["resp_port"] = INTEGER(orig_port_dst);

  // Layer 3 (AF) - IPv4 and IPv6
  src_addr.ss_family = nfct_get_attr_u8(ec->event.get(), ATTR_ORIG_L3PROTO);
  dst_addr.ss_family = src_addr.ss_family;

  switch (src_addr.ss_family) {
  case AF_INET: {
    struct nfct_attr_grp_ipv4 ipv4;
    nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_IPV4, &ipv4);
    ((struct sockaddr_in*)&src_addr)->sin_addr.s_addr = ipv4.src;
    ((struct sockaddr_in*)&dst_addr)->sin_addr.s_addr = ipv4.dst;

    r["orig_address"] =
        std::string{inet_ntoa(((struct sockaddr_in*)&src_addr)->sin_addr)};
    r["resp_address"] =
        std::string{inet_ntoa(((struct sockaddr_in*)&dst_addr)->sin_addr)};

    ((struct sockaddr_in*)&src_addr)->sin_port = orig_port_src;
    ((struct sockaddr_in*)&dst_addr)->sin_port = orig_port_dst;
  } break;

  case AF_INET6: {
    struct nfct_attr_grp_ipv6 ipv6;
    nfct_get_attr_grp(ec->event.get(), ATTR_GRP_ORIG_IPV6, &ipv6);
    memcpy(&((struct sockaddr_in6*)&src_addr)->sin6_addr.s6_addr32,
           &ipv6.src,
           sizeof(ipv6.src));
    memcpy(&((struct sockaddr_in6*)&dst_addr)->sin6_addr.s6_addr32,
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

    ((struct sockaddr_in6*)&src_addr)->sin6_port = orig_port_src;
    ((struct sockaddr_in6*)&dst_addr)->sin6_port = orig_port_dst;
  } break;
  // TODO: Add more L3 Protocols
  default:
    LOG(WARNING) << "Unsupported level 3 protocol number: " +
                        std::to_string(src_addr.ss_family);
  }

  // Others
  r["time"] = "";
  r["inode"] = "";
  r["fd"] = "";
  r["pid"] = "";

  // Find the inode - Search among entries of protocol in /proc/net
  int orig_l4proto = nfct_get_attr_u8(ec->event.get(), ATTR_ORIG_L4PROTO);
  tables::InodeMap inodes;
  std::vector<std::string> matched_inodes;
  QueryData results;
  tables::genSocketsFromProc(inodes, orig_l4proto, src_addr.ss_family, results);

  // TODO: Broadcast addresses does not seems to match (/proc <-> conntrack)
  for (osquery::Row& result : results) {
    if ((result["local_address"] == r["orig_address"] &&
         result["remote_address"] == r["resp_address"] &&
         result["protocol"] == r["protocol"] &&
         result["local_port"] == r["orig_port"] &&
         result["remote_port"] == r["resp_port"]) ||
        (result["local_address"] == r["resp_address"] &&
         result["remote_address"] == r["orig_address"] &&
         result["protocol"] == r["protocol"] &&
         result["local_port"] == r["resp_port"] &&
         result["remote_port"] == r["orig_port"])) {
      matched_inodes.push_back(result["socket"]);
    }
  }
  // assert(matched_inodes.size() <= 1);
  if (matched_inodes.size() == 0) {
    add(r);
    return Status(0, "No inode found");
  }
  r["inode"] = matched_inodes.at(0);

  // Find the process to the respective inode - Search among the entries in
  // /proc/<pid>/fd
  inodes.clear();
  std::set<std::string> pids;
  procProcesses(pids);
  for (const auto& process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      for (const auto& fd : descriptors) {
        if (fd.second.find("socket:[") == 0) {
          // See #792: std::regex is incomplete until GCC 4.9 (skip 8 chars)
          auto inode = fd.second.substr(8);
          inodes[inode.substr(0, inode.size() - 1)] =
              std::make_pair(fd.first, process);
        }
      }
    }
  }

  if (inodes.count(r["inode"]) == 0) {
    add(r);
    return Status(0, "No process for inode found");
  }
  r["fd"] = inodes[r["inode"]].first;
  r["pid"] = inodes[r["inode"]].second;

  // A callback is somewhat useless unless it changes the EventSubscriber
  // state or calls `add` to store a marked up event.
  add(r);

  return Status(0, "OK");
}
}
