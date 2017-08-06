/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/replace.hpp>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/networking/windows/interfaces.h"

namespace osquery {
namespace tables {

const std::map<unsigned short, const std::string> kMapOfAddressFamily = {
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
  WmiRequest wmiSystemReq("select * from MSFT_NetNeighbor",
                          (BSTR)L"ROOT\\StandardCimv2");
  auto& wmiResults = wmiSystemReq.results();
  std::map<long, std::string> mapOfInterfaces = {
      {1, ""}, // loopback
  };
  unsigned short usiPlaceHolder;
  unsigned char cPlaceHolder;
  unsigned int uiPlaceHolder;
  std::string strPlaceHolder;

  for (const auto& iface : interfaces) {
    long interfaceIndex;

    if (iface.count("interface") > 0) {
      safeStrtol(iface.at("interface"), 10, interfaceIndex);
      mapOfInterfaces[interfaceIndex] =
          iface.count("mac") > 0 ? iface.at("mac") : "";
    }
  }

  for (const auto& item : wmiResults) {
    Row r;
    item.GetUnsignedShort("AddressFamily", usiPlaceHolder);
    r["address_family"] = kMapOfAddressFamily.count(usiPlaceHolder) > 0
                              ? kMapOfAddressFamily.at(usiPlaceHolder)
                              : "-1";
    item.GetUChar("Store", cPlaceHolder);
    r["store"] = kMapOfStore.count(cPlaceHolder) > 0
                     ? kMapOfStore.at(cPlaceHolder)
                     : "-1";
    item.GetUChar("State", cPlaceHolder);
    r["state"] = kMapOfState.count(cPlaceHolder) > 0
                     ? kMapOfState.at(cPlaceHolder)
                     : "-1";
    item.GetUnsignedInt32("InterfaceIndex", uiPlaceHolder);
    r["interface"] = mapOfInterfaces.count(uiPlaceHolder) > 0
                         ? mapOfInterfaces.at(uiPlaceHolder)
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
