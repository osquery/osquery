/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
// Small hack to make the header compatible with C++
#define prf_ra in6_prflags::prf_ra
#include <netinet6/nd6.h>
#undef prf_ra
// clang-format on

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>
#include <osquery/tables/networking/posix/interfaces.h>

namespace osquery {
namespace tables {

namespace {
const std::unordered_map<std::string, std::tuple<int, int>> kIpv6SysctlObjects =
    {
        {"forwarding_enabled", {IPPROTO_IPV6, IPV6CTL_FORWARDING}},
        {"redirect_accept", {IPPROTO_ICMPV6, ICMPV6CTL_REDIRACCEPT}},
        {"hop_limit", {IPPROTO_IPV6, IPV6CTL_DEFHLIM}},
        {"rtadv_accept", {IPPROTO_IPV6, IPV6CTL_ACCEPT_RTADV}},
};

int getSysIpv6Config(const std::string& attr) {
  int value;
  size_t size = sizeof(value);
  auto sysctlObject = kIpv6SysctlObjects.find(attr);
  if (sysctlObject == kIpv6SysctlObjects.end()) {
    VLOG(1) << "No such sysctl object identifier: \"" << attr << "\"";
    return -1;
  }
  auto proto = std::get<0>(sysctlObject->second);
  auto object = std::get<1>(sysctlObject->second);
  int mib[] = {CTL_NET, PF_INET6, proto, object};
  return sysctl(mib, 4, &value, &size, nullptr, 0) < 0 ? -1 : value;
}
} // namespace

void genIpv6FromIntf(const std::string& iface, QueryData& results) {
  Row r;
  int ifaceHlim = 0;
  int ifaceRtadv = 0;

  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd >= 0) {
    struct in6_ndireq nd;
    memcpy(nd.ifname, iface.c_str(), sizeof(nd.ifname));
    if (ioctl(fd, SIOCGIFINFO_IN6, &nd) >= 0) {
      ifaceHlim = nd.ndi.chlim;
      ifaceRtadv = nd.ndi.flags & ND6_IFF_ACCEPT_RTADV;
    } else {
      VLOG(1) << "Error getting information from intf: " << iface;
    }
    close(fd);
  } else {
    VLOG(1) << "Cannot open inet6 socket";
  }

  r["interface"] = iface;
  r["hop_limit"] =
      INTEGER(ifaceHlim ? ifaceHlim : getSysIpv6Config("hop_limit"));
  r["rtadv_accept"] =
      INTEGER(getSysIpv6Config("rtadv_accept") > 0 && ifaceRtadv);
  // FreeBSD does not support some of the configurations at the interface level
  for (const auto& attr : {"forwarding_enabled", "redirect_accept"}) {
    r[attr] = INTEGER(getSysIpv6Config(attr));
  }
  results.emplace_back(std::move(r));
}

QueryData genInterfaceIpv6(QueryContext& context) {
  QueryData results;
  for (const auto& iface : genInterfaceDetails(context)) {
    genIpv6FromIntf(iface.at("interface"), results);
  }
  return results;
}
} // namespace tables
} // namespace osquery
