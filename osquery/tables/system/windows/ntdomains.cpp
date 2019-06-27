/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genNtdomains(QueryContext& context) {
  QueryData results;

  WmiRequest wmiSystemReq("select * from Win32_NtDomain");
  const auto& wmiResults = wmiSystemReq.results();
  if (wmiSystemReq.getStatus().ok()) {
    if (!wmiResults.empty()) {
      for (const auto& data : wmiResults) {
        Row r;
        data.GetString("Name", r["name"]);
        data.GetString("ClientSiteName", r["client_site_name"]);
        data.GetString("DcSiteName", r["dc_site_name"]);
        data.GetString("DnsForestName", r["dns_forest_name"]);
        data.GetString("DomainControllerAddress",
                       r["domain_controller_address"]);
        data.GetString("DomainControllerName", r["domain_controller_name"]);
        data.GetString("DomainName", r["domain_name"]);
        data.GetString("Status", r["status"]);
        results.push_back(std::move(r));
      }
    } else {
      LOG(WARNING) << "WMI resultset empty.";
    }
  } else {
    VLOG(1) << wmiSystemReq.getStatus().getMessage();
  }
  return results;
}
} // namespace tables
} // namespace osquery
