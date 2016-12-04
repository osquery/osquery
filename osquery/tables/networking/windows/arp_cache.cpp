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
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

  const std::map<unsigned short, const std::string> mapOfAddressFamily = {
    {2, "IPv4"},
    {23, "IPv6"},
  };

  const std::map<unsigned char, const std::string> mapOfStore = {
    {0, "Persistent"},
    {1, "Active"},
  };

  const std::map<unsigned char, const std::string> mapOfState = {
    {0, "Unreachable"},
    {1, "Incomplete"},
    {2, "Probe"},
    {3, "Delay"},
    {4, "Stale"},
    {5, "Reachable"},
    {6, "Permenant"},
    {7, "TBD"},
  };

  QueryData genArpCache(QueryContext& context) {
    QueryData results;

    WmiRequest wmiSystemReq("select * from MSFT_NetNeighbor where InterfaceIndex", L"ROOT\\StandardCimv2");
    std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();

    if (wmiResults.size() != 0) {
      Row r;

      for (const auto& item : wmiResults) {
        unsigned short usiPlaceHolder;
        unsigned char cPlaceHolder;
        unsigned int uiPlaceHolder;

        item.GetUnsignedShort("AddressFamily", usiPlaceHolder);
        r["address_family"] = SQL_TEXT(mapOfAddressFamily.at(usiPlaceHolder));
        item.GetUChar("Store", cPlaceHolder);
        r["store"] = SQL_TEXT(mapOfStore.at(cPlaceHolder));
        item.GetUChar("State", cPlaceHolder);
        r["state"] = SQL_TEXT(mapOfState.at(cPlaceHolder));
        item.GetUnsignedInt32("InterfaceIndex", uiPlaceHolder);
        r["interface_index"] = INTEGER(uiPlaceHolder);
        item.GetString("IPAddress", r["ip_address"]);
        item.GetString("InterfaceAlias", r["interface_alias"]);
        item.GetString("LinkLayerAddress", r["link_layer_address"]);

        results.push_back(r);
      }
    }

    return results;
  }
}
}
