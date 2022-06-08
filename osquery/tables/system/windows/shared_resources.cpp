/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#include "osquery/core/windows/wmi.h"
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

QueryData genShares(QueryContext& context) {
  QueryData results_data;

  const auto request =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_Share");
  if (request && request->getStatus().ok()) {
    const std::vector<WmiResultItem>& results = request->results();
    for (const auto& result : results) {
      Row r;
      long lPlaceHolder;
      bool bPlaceHolder;

      result.GetString("Description", r["description"]);
      result.GetString("InstallDate", r["install_date"]);
      result.GetString("Status", r["status"]);
      auto status = result.GetBool("AllowMaximum", bPlaceHolder);
      r["allow_maximum"] = status ? INTEGER(bPlaceHolder) : "-1";
      status = result.GetLong("MaximumAllowed", lPlaceHolder);
      r["maximum_allowed"] = status ? INTEGER(lPlaceHolder) : "-1";
      result.GetString("Name", r["name"]);
      result.GetString("Path", r["path"]);
      status = result.GetLong("Type", lPlaceHolder);
      r["type"] = status ? INTEGER(lPlaceHolder) : "-1";

      results_data.push_back(r);
    }
  }

  return results_data;
}
} // namespace tables
} // namespace osquery
