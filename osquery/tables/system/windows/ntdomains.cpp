/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genNtdomains(QueryContext& context) {
  QueryData results;

  Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest("select * from Win32_NtDomain");
  if (wmiSystemReq) {
    const auto& wmiResults = wmiSystemReq->results();
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
    VLOG(1) << wmiSystemReq.getError().getMessage();
  }
  return results;
}
} // namespace tables
} // namespace osquery
