/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/replace.hpp>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/networking/windows/interfaces.h"

namespace osquery {
namespace tables {

const std::map<long, const std::string> kMapOfAddressFamily = {
    {2, "IPv4"}, {23, "IPv6"},
};

const std::map<unsigned char, const std::string> kMapOfStore = {
    {0, "Persistent"}, {1, "Active"},
};

const std::map<unsigned char, const std::string> kMapOfState = {
    {0, "Unreachable"},
    {1, "Incomplete"},
    {2, "Probe"},
    {3, "Delay"},
    {4, "Stale"},
    {5, "Reachable"},
    {6, "Permanent"},
    {7, "TBD"},
};

QueryData genIPv4ArpCache(QueryContext& context) {
  QueryData results;
  auto interfaces = genInterfaceDetails(context);
  const WmiRequest wmiSystemReq("select * from MSFT_NetNeighbor",
                                (BSTR)L"ROOT\\StandardCimv2");
  const auto& wmiResults = wmiSystemReq.results();
  std::map<long, std::string> mapOfInterfaces = {
      {1, ""}, // loopback
  };

  for (const auto& iface : interfaces) {

    if (iface.count("interface") > 0) {
      long interface_index = tryTo<long>(iface.at("interface"), 10).getOr(0l);
      mapOfInterfaces[interface_index] =
          iface.count("mac") > 0 ? iface.at("mac") : "";
    }
  }

  long lPlaceHolder = 0;
  unsigned char cPlaceHolder;
  std::string strPlaceHolder;
  for (const auto& item : wmiResults) {
    Row r;
    item.GetLong("AddressFamily", lPlaceHolder);
    r["address_family"] = kMapOfAddressFamily.count(lPlaceHolder) > 0
                              ? kMapOfAddressFamily.at(lPlaceHolder)
                              : "-1";
    item.GetUChar("Store", cPlaceHolder);
    r["store"] = kMapOfStore.count(cPlaceHolder) > 0
                     ? kMapOfStore.at(cPlaceHolder)
                     : "-1";
    item.GetUChar("State", cPlaceHolder);
    r["state"] = kMapOfState.count(cPlaceHolder) > 0
                     ? kMapOfState.at(cPlaceHolder)
                     : "-1";
    item.GetLong("InterfaceIndex", lPlaceHolder);
    r["interface"] = mapOfInterfaces.count(lPlaceHolder) > 0
                         ? mapOfInterfaces.at(lPlaceHolder)
                         : "-1";
    item.GetString("IPAddress", r["ip_address"]);
    item.GetString("InterfaceAlias", r["interface_alias"]);
    item.GetString("LinkLayerAddress", strPlaceHolder);
    r["link_layer_address"] = boost::replace_all_copy(strPlaceHolder, "-", ":");
    results.push_back(r);
  }

  return results;
}

QueryData genArpCache(QueryContext& context) {
  QueryData results;
  QueryData winArpCache = genIPv4ArpCache(context);

  for (const auto& item : winArpCache) {
    if (item.at("link_layer_address").empty() ||
        item.at("link_layer_address") == "00:00:00:00:00:00") {
      continue;
    }
    if (item.at("address_family") == "IPv4") {
      Row r;
      r["address"] = item.at("ip_address");
      r["mac"] = item.at("link_layer_address");
      r["interface"] = item.at("interface");
      r["permanent"] = "Permanent" == item.at("state") ? "1" : "0";
      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
