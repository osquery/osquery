/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <string>

#include <stdlib.h>

#include <boost/algorithm/string/join.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {

void genAddresses(QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM win32_networkadapterconfiguration where IPEnabled=TRUE";

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      std::vector<std::string> vPlaceHolderIps;
      std::vector<std::string> vPlaceHolderSubnets;

      result.GetLong("InterfaceIndex", lPlaceHolder);
      std::stringstream interface_index;
      interface_index << lPlaceHolder;
      r["interface"] = SQL_TEXT(interface_index.str());
      result.GetVectorOfStrings("IPAddress", vPlaceHolderIps);
      result.GetVectorOfStrings("IPSubnet", vPlaceHolderSubnets);
      for (size_t i = 0; i < vPlaceHolderIps.size(); i++) {
        r["address"] = SQL_TEXT(vPlaceHolderIps.at(i));
        if (vPlaceHolderSubnets.size() > i) {
          r["mask"] = SQL_TEXT(vPlaceHolderSubnets.at(i));
        }
        results_data.push_back(r);
      }
    }
  }
}

void genDetails(QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM Win32_NetworkAdapter";

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      bool bPlaceHolder;
      std::vector<std::string> vPlaceHolder;
      unsigned __int64 ulPlaceHolder;

      result.GetString("AdapterType", r["type"]);
      result.GetString("Description", r["description"]);
      result.GetLong("InterfaceIndex", lPlaceHolder);
      r["interface"] = INTEGER(lPlaceHolder);
      result.GetString("MACAddress", r["mac"]);
      result.GetString("Manufacturer", r["manufacturer"]);
      result.GetString("NetConnectionID", r["connection_id"]);
      result.GetLong("NetConnectionStatus", lPlaceHolder);
      r["connection_status"] = INTEGER(lPlaceHolder);
      result.GetBool("NetEnabled", bPlaceHolder);
      r["enabled"] = INTEGER(bPlaceHolder);
      result.GetBool("PhysicalAdapter", bPlaceHolder);
      r["physical_adapter"] = INTEGER(bPlaceHolder);
      result.GetUnsignedLongLong("Speed", ulPlaceHolder);
      r["speed"] = INTEGER(ulPlaceHolder);

      std::stringstream iss;
      iss << "SELECT * FROM win32_networkadapterconfiguration WHERE "
             "InterfaceIndex = "
          << r["interface"];

      WmiRequest irequest(iss.str());
      if (irequest.getStatus().ok()) {
        std::vector<WmiResultItem>& iresults = irequest.results();

        iresults[0].GetBool("DHCPEnabled", bPlaceHolder);
        r["dhcp_enabled"] = INTEGER(bPlaceHolder);
        iresults[0].GetString("DHCPLeaseExpires", r["dhcp_lease_expires"]);
        iresults[0].GetString("DHCPLeaseObtained", r["dhcp_lease_obtained"]);
        iresults[0].GetString("DHCPServer", r["dhcp_server"]);
        iresults[0].GetString("DNSDomain", r["dns_domain"]);
        iresults[0].GetVectorOfStrings("DNSDomainSuffixSearchOrder",
                                       vPlaceHolder);
        r["dns_domain_suffix_search_order"] =
            SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
        iresults[0].GetString("DNSHostName", r["dns_host_name"]);
        iresults[0].GetVectorOfStrings("DNSServerSearchOrder", vPlaceHolder);
        r["dns_server_search_order"] =
            SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
      }
      results_data.push_back(r);
    }
  }
}

QueryData genInterfaceDetails(QueryContext& context) {
  QueryData results;
  genDetails(results);

  return results;
}

QueryData genInterfaceAddresses(QueryContext& context) {
  QueryData results;
  genAddresses(results);

  return results;
}
}
}