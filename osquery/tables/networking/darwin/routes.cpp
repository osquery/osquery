// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>

#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sysctl.h>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

typedef std::pair<int, std::string> RouteType;
typedef std::map<int, std::string> InterfaceMap;

const std::string kDefaultRoute = "0.0.0.0";

const std::vector<RouteType> kRouteTypes = {
    std::make_pair(RTF_LOCAL, "local"),
    std::make_pair(RTF_GATEWAY, "gateway"),
    std::make_pair(RTF_HOST, "host"),
    std::make_pair(RTF_DYNAMIC, "dynamic"),
    std::make_pair(RTF_MODIFIED, "modified"),
    std::make_pair(RTF_LLINFO, "linklayer"),
    std::make_pair(RTF_STATIC, "static"),
    std::make_pair(RTF_BLACKHOLE, "blackhole"),
    std::make_pair(RTF_ROUTER, "router"),
    std::make_pair(RTF_PROXY, "proxy"), };

InterfaceMap genInterfaceMap() {
  InterfaceMap ifmap;

  struct ifaddrs *if_addrs, *if_addr;
  struct sockaddr_dl *sdl;

  if (getifaddrs(&if_addrs) != 0) {
    LOG(ERROR) << "Failed to create interface map, getifaddrs() failed.";
    return ifmap;
  }

  InterfaceMap::iterator it = ifmap.begin();
  for (if_addr = if_addrs; if_addr != NULL; if_addr = if_addr->ifa_next) {
    if (if_addr->ifa_addr != NULL && if_addr->ifa_addr->sa_family == AF_LINK) {
      sdl = (struct sockaddr_dl *)if_addr->ifa_addr;
      ifmap.insert(
          it, std::make_pair(sdl->sdl_index, std::string(if_addr->ifa_name)));
    }
  }

  freeifaddrs(if_addrs);
  return ifmap;
}

void genRouteTableType(RouteType type, InterfaceMap ifmap, QueryData &results) {
  int mib[] = {CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_FLAGS, type.first};
  size_t table_size;
  char *table, *p;
  struct rt_msghdr *route;
  struct sockaddr *sa;
  struct sockaddr *sa_table[RTAX_MAX];
  struct sockaddr_dl *sdl;

  if (sysctl(mib, sizeof(mib) / sizeof(int), 0, &table_size, 0, 0) < 0) {
    return;
  }

  if (table_size == 0) {
    return;
  }

  table = (char *)malloc(table_size);
  if (sysctl(mib, sizeof(mib) / sizeof(int), table, &table_size, 0, 0) < 0) {
    free(table);
    return;
  }

  for (p = table; p < table + table_size; p += route->rtm_msglen) {
    route = (struct rt_msghdr *)p;
    sa = (struct sockaddr *)(route + 1);

    // Populate route's sockaddr table (dest, gw, mask).
    for (int i = 0; i < RTAX_MAX; i++) {
      if (route->rtm_addrs & (1 << i)) {
        sa_table[i] = sa;
        sa = (struct sockaddr *)((char *)sa + (sa->sa_len));
      } else {
        sa_table[i] = NULL;
      }
    }

    Row r;
    r["type"] = type.second;
    r["flags"] = boost::lexical_cast<std::string>(route->rtm_flags);
    r["use"] = boost::lexical_cast<std::string>(route->rtm_use);
    r["mtu"] = boost::lexical_cast<std::string>(route->rtm_rmx.rmx_mtu);

    if ((route->rtm_addrs & RTA_DST) == RTA_DST) {
      r["destination"] = canonical_ip_address(sa_table[RTAX_DST]);
    }

    if ((route->rtm_addrs & RTA_GATEWAY) == RTA_GATEWAY) {
      sdl = (struct sockaddr_dl *)sa_table[RTAX_GATEWAY];
      r["interface"] = ifmap[(int)sdl->sdl_index];
      r["gateway"] = canonical_ip_address(sa_table[RTAX_GATEWAY]);
    }

    if (kDefaultRoute.compare(r["destination"]) == 0) {
      r["netmask"] = kDefaultRoute;
    } else if ((route->rtm_addrs & RTA_NETMASK) == RTA_NETMASK) {
      sa_table[RTAX_NETMASK]->sa_family = sa_table[RTAX_DST]->sa_family;
      r["netmask"] = canonical_ip_address(sa_table[RTAX_NETMASK]);
    }

    results.push_back(r);
  }

  free(table);
}

QueryData genRoutes() {
  QueryData results;
  InterfaceMap ifmap;

  // Need a map from index->name for each route entry.
  ifmap = genInterfaceMap();

  for (const auto &route_type : kRouteTypes) {
    genRouteTableType(route_type, ifmap, results);
  }

  return results;
}
}
}
