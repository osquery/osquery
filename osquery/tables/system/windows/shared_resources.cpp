/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

#define DECLARE_TABLE_IMPLEMENTATION_shared_resources
#include <generated/tables/tbl_shared_resources_defs.hpp>

namespace osquery {
namespace tables {

QueryData genShares(QueryContext& context) {
  QueryData results_data;

  WmiRequest request("SELECT * FROM Win32_Share");
  if (request.getStatus().ok()) {
    std::vector<WmiResultItem>& results = request.results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      bool bPlaceHolder;

      result.GetString("Description", r["description"]);
      result.GetString("InstallDate", r["install_date"]);
      result.GetString("Status", r["status"]);
      result.GetBool("AllowMaximum", bPlaceHolder);
      r["allow_maximum"] = INTEGER(bPlaceHolder);
      result.GetLong("MaximumAllowed", lPlaceHolder);
      r["maximum_allowed"] = INTEGER(lPlaceHolder);
      result.GetString("Name", r["name"]);
      result.GetString("Path", r["path"]);
      result.GetLong("Type", lPlaceHolder);
      r["type"] = INTEGER(lPlaceHolder);
      results_data.push_back(r);
    }
  }

  return results_data;
}
}
}