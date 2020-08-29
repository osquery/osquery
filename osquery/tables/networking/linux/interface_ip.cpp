/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/networking/posix/interfaces.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {
const std::string kIpv6SysConfig = "all";
const std::unordered_map<std::string, std::string> kIpv6ProcEntry = {
    {"forwarding_enabled", "forwarding"},
    {"redirect_accept", "accept_redirects"},
    {"hop_limit", "hop_limit"},
    {"rtadv_accept", "accept_ra"},
};

inline std::string getIpv6Attr(const std::string& intf,
                               const std::string& attr) {
  return "/proc/sys/net/ipv6/conf/" + intf + "/" + kIpv6ProcEntry.at(attr);
}

int getIpv6Config(const std::string& attr,
                  const std::string& intf = kIpv6SysConfig) {
  std::string content;
  auto ipv6Attr = getIpv6Attr(intf, attr);
  if (readFile(ipv6Attr, content).ok()) {
    boost::trim(content);
    auto ret = tryTo<int>(content);
    if (ret.isValue()) {
      return ret.get();
    }
  }
  return -1;
}
} // namespace

void genIpv6FromIntf(const std::string& iface, QueryData& results) {
  Row r;
  /*
   * The "real value" of an entry depends on both the global and local
   * setting. Depending on the entry, the local setting may get ORed, ANDed, or
   * MAXed with the global setting.
   * More information:
   *   - linux/Documentation/networking/ip-sysctl.txt
   *   - linux/include/linux/inetdevice.h
   */
  r["interface"] = iface;
  r["hop_limit"] = INTEGER(getIpv6Config("hop_limit", iface));
  int forwarding = getIpv6Config("forwarding_enabled", iface);
  r["forwarding_enabled"] = INTEGER(forwarding);
  int redirect = getIpv6Config("redirect_accept");
  int ifaceRedirect = getIpv6Config("redirect_accept", iface);
  r["redirect_accept"] = INTEGER(forwarding ? redirect && ifaceRedirect
                                            : redirect || ifaceRedirect);
  int rtadv = getIpv6Config("rtadv_accept", iface);
  r["rtadv_accept"] = INTEGER(rtadv == 2 ? 1 : rtadv && (!forwarding));
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
