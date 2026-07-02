/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD routes: dump the kernel routing table via
 * sysctl(CTL_NET.PF_ROUTE.NET_RT_DUMP), walk the chain of rt_msghdr +
 * trailing sockaddrs that the kernel returns, and emit one row per route.
 *
 * Adapted from osquery's Darwin implementation (same routing socket API).
 * Differences:
 *   * RTF_PROXY and RTF_ROUTER don't exist on FreeBSD (Darwin-only).  We
 *     drop those entries from kRouteTypes.
 *   * sa_len rounding for sockaddr stride uses the same SA_SIZE() macro
 *     as netstat(1) (round to sizeof(long)) -- the simpler "+sa->sa_len"
 *     stride works for the common case but mis-aligns when sa_len is 0
 *     or not a multiple of long.
 */

#include <iomanip>
#include <string>
#include <vector>

#include <ifaddrs.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>

#ifndef SA_SIZE
#define SA_SIZE(sa)                                                            \
  ((!(sa) || ((struct sockaddr*)(sa))->sa_len == 0)                            \
       ? sizeof(long)                                                          \
       : 1 + ((((struct sockaddr*)(sa))->sa_len - 1) | (sizeof(long) - 1)))
#endif

namespace osquery {
namespace tables {

typedef std::pair<int, std::string> RouteType;
typedef std::map<int, std::string> InterfaceMap;
typedef std::vector<struct sockaddr*> AddressMap;

constexpr auto kDefaultIPv4Route = "0.0.0.0";
constexpr auto kDefaultIPv6Route = "::";

// FreeBSD flag set, minus Darwin-only RTF_PROXY and RTF_ROUTER.
const std::vector<RouteType> kRouteTypes = {
    std::make_pair(RTF_LOCAL, "local"),
    std::make_pair(RTF_GATEWAY, "gateway"),
    std::make_pair(RTF_DYNAMIC, "dynamic"),
    std::make_pair(RTF_MODIFIED, "modified"),
    std::make_pair(RTF_STATIC, "static"),
    std::make_pair(RTF_BLACKHOLE, "blackhole"),
};

InterfaceMap genInterfaceMap() {
  InterfaceMap ifmap;
  struct ifaddrs *if_addrs = nullptr, *if_addr = nullptr;
  if (getifaddrs(&if_addrs) != 0 || if_addrs == nullptr) {
    return ifmap;
  }
  for (if_addr = if_addrs; if_addr != nullptr; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr != nullptr &&
        if_addr->ifa_addr->sa_family == AF_LINK) {
      auto sdl = (struct sockaddr_dl*)if_addr->ifa_addr;
      ifmap[sdl->sdl_index] = std::string(if_addr->ifa_name);
    }
  }
  freeifaddrs(if_addrs);
  return ifmap;
}

static Status genRoute(const struct rt_msghdr* route,
                       const AddressMap& addr_map,
                       Row& r) {
  r["flags"] = INTEGER(route->rtm_flags);
  r["mtu"] = INTEGER(route->rtm_rmx.rmx_mtu);
  r["hopcount"] = INTEGER(route->rtm_rmx.rmx_hopcount);

  if ((route->rtm_addrs & RTA_DST) == RTA_DST &&
      addr_map[RTAX_DST] != nullptr) {
    r["destination"] = ipAsString(addr_map[RTAX_DST]);
  }
  if ((route->rtm_addrs & RTA_GATEWAY) == RTA_GATEWAY &&
      addr_map[RTAX_GATEWAY] != nullptr) {
    r["gateway"] = ipAsString(addr_map[RTAX_GATEWAY]);
  }

  if (r["destination"] == kDefaultIPv4Route ||
      r["destination"] == kDefaultIPv6Route) {
    r["netmask"] = "0";
  } else if ((route->rtm_addrs & RTA_NETMASK) == RTA_NETMASK &&
             addr_map[RTAX_NETMASK] != nullptr &&
             addr_map[RTAX_DST] != nullptr) {
    addr_map[RTAX_NETMASK]->sa_family = addr_map[RTAX_DST]->sa_family;
    r["netmask"] = INTEGER(netmaskFromIP(addr_map[RTAX_NETMASK]));
  } else {
    if (addr_map[RTAX_DST] != nullptr &&
        addr_map[RTAX_DST]->sa_family == AF_INET6) {
      r["netmask"] = "128";
    } else {
      r["netmask"] = "32";
    }
  }

  r["source"] = "";
  r["metric"] = "0";
  return Status::success();
}

static void genRouteTableType(RouteType type,
                              InterfaceMap ifmap,
                              QueryData& results) {
  size_t table_size = 0;
  int mib[] = {CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_FLAGS, type.first};
  if (sysctl(mib, sizeof(mib) / sizeof(int), nullptr, &table_size, nullptr, 0) <
          0 ||
      table_size == 0) {
    return;
  }

  std::vector<char> table(table_size);
  if (sysctl(mib,
             sizeof(mib) / sizeof(int),
             table.data(),
             &table_size,
             nullptr,
             0) < 0) {
    return;
  }

  size_t message_length = 0;
  for (char* p = table.data(); p < table.data() + table_size;
       p += message_length) {
    auto route = (struct rt_msghdr*)p;
    auto sa = (struct sockaddr*)(route + 1);
    message_length = route->rtm_msglen;
    if (message_length == 0) {
      break;
    }

    AddressMap addr_map;
    for (int i = 0; i < RTAX_MAX; i++) {
      if (route->rtm_addrs & (1 << i)) {
        addr_map.push_back(sa);
        sa = (struct sockaddr*)((char*)sa + SA_SIZE(sa));
      } else {
        addr_map.push_back(nullptr);
      }
    }

    Row r;
    if ((route->rtm_addrs & RTA_GATEWAY) == RTA_GATEWAY) {
      r["interface"] = ifmap[(int)route->rtm_index];
    }
    r["type"] = type.second;
    if (genRoute(route, addr_map, r).ok()) {
      results.push_back(r);
    }
  }
}

QueryData genRoutes(QueryContext& context) {
  QueryData results;
  InterfaceMap ifmap = genInterfaceMap();
  for (const auto& route_type : kRouteTypes) {
    if (context.constraints["type"].notExistsOrMatches(route_type.second)) {
      genRouteTableType(route_type, ifmap, results);
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
