/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>
#include <sstream>

#include <stdlib.h>

#include <boost/algorithm/string/join.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/wmi.h"

namespace osquery {
namespace tables {

void genInterfaces(QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM Win32_NetworkAdapter";

  WmiRequest request(ss.str());
  if (request.getStatus().ok()) {
	std::vector<WmiResultItem>& results = request.results();
	for (const auto& result : results) {
		Row r;
		Status s;
		long lPlaceHolder;
		bool bPlaceHolder;
		std::string sPlaceHolder;
		std::vector<std::string> vPlaceHolder;
		unsigned __int64 ulPlaceHolder;


		s = result.GetString("AdapterType", sPlaceHolder);
		r["adapter_type"] = SQL_TEXT(sPlaceHolder);
		s = result.GetLong("AdapterTypeID", lPlaceHolder);
		r["adapter_type_id"] = INTEGER(lPlaceHolder);
		s = result.GetString("Caption", sPlaceHolder);
		r["caption"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Description", sPlaceHolder);
		r["description"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("GUID", sPlaceHolder);
		r["guid"] = SQL_TEXT(sPlaceHolder);
		s = result.GetLong("InterfaceIndex", lPlaceHolder);
		r["interface_index"] = INTEGER(lPlaceHolder);
		s = result.GetString("MACAddress", sPlaceHolder);
		r["mac_address"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Manufacturer", sPlaceHolder);
		r["manufacturer"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("Name", sPlaceHolder);
		r["name"] = SQL_TEXT(sPlaceHolder);
		s = result.GetString("NetConnectionID", sPlaceHolder);
		r["net_connection_id"] = SQL_TEXT(sPlaceHolder);
		s = result.GetLong("NetConnectionStatus", lPlaceHolder);
		r["net_connection_status"] = INTEGER(lPlaceHolder);
		s = result.GetBool("NetEnabled", bPlaceHolder);
		r["net_enabled"] = INTEGER(bPlaceHolder);
		s = result.GetBool("PhysicalAdapter", bPlaceHolder);
		r["physical_adapter"] = INTEGER(bPlaceHolder);
		s = result.GetString("ServiceName", sPlaceHolder);
		r["service_name"] = SQL_TEXT(sPlaceHolder);
		s = result.GetUnsignedLongLong("Speed", ulPlaceHolder);
		r["speed"] = INTEGER(ulPlaceHolder);

		std::stringstream iss;
		iss << "SELECT * FROM win32_networkadapterconfiguration WHERE InterfaceIndex = " << r["interface_index"];

		WmiRequest irequest(iss.str());
		if (irequest.getStatus().ok()) {
			std::vector<WmiResultItem>& iresults = irequest.results();
			
			s = iresults[0].GetVectorOfStrings("DefaultIPGateway", vPlaceHolder);
			r["default_gateway"] = SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
			s = iresults[0].GetBool("DHCPEnabled", bPlaceHolder);
			r["dhcp_enabled"] = INTEGER(bPlaceHolder);
			s = iresults[0].GetString("DHCPLeaseExpires", sPlaceHolder);
			r["dhcp_lease_expires"] = SQL_TEXT(sPlaceHolder);
			s = iresults[0].GetString("DHCPLeaseObtained", sPlaceHolder);
			r["dhcp_lease_obtained"] = SQL_TEXT(sPlaceHolder);
			s = iresults[0].GetString("DHCPServer", sPlaceHolder);
			r["dhcp_server"] = SQL_TEXT(sPlaceHolder);
			s = iresults[0].GetString("DNSDomain", sPlaceHolder);
			r["dns_domain"] = SQL_TEXT(sPlaceHolder);
			s = iresults[0].GetVectorOfStrings("DNSDomainSuffixSearchOrder", vPlaceHolder);
			r["dns_domain_suffix_search_order"] = SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
			s = iresults[0].GetBool("DNSEnabledForWINSResolution", bPlaceHolder);
			r["dns_enabled_for_wins_resolution"] = INTEGER(bPlaceHolder);
			s = iresults[0].GetString("DNSHostName", sPlaceHolder);
			r["dns_host_name"] = SQL_TEXT(sPlaceHolder);
			s = iresults[0].GetVectorOfStrings("DNSServerSearchOrder", vPlaceHolder);
			r["dns_server_search_order"] = SQL_TEXT(boost::algorithm::join(vPlaceHolder, ", "));
		}
		results_data.push_back(r);
	}
  }
}

QueryData genWinInterfaceDetails(QueryContext& context) {
  QueryData results;
  genInterfaces(results);

  return results;
}
}
}