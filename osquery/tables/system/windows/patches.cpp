/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genInstalledPatches(QueryContext& context) {
  QueryData results;

  const auto wmiSystemReq =
      WmiRequest::CreateWmiRequest("select * from Win32_QuickFixEngineering");

  if (wmiSystemReq && !wmiSystemReq->results().empty()) {
    const auto& wmiResults = wmiSystemReq->results();
    Row r;

    for (const auto& item : wmiResults) {
      item.GetString("CSName", r["csname"]);
      item.GetString("HotFixID", r["hotfix_id"]);
      item.GetString("Caption", r["caption"]);
      item.GetString("Description", r["description"]);
      item.GetString("FixComments", r["fix_comments"]);
      item.GetString("InstalledBy", r["installed_by"]);
      r["install_date"] = "";

      std::string installedOn;
      item.GetString("InstalledOn", installedOn);
      r["installed_on"] = installedOn;

      auto unixTime = parseDateToUnixTime(installedOn);
      r["installed_on_unix"] = (unixTime > 0) ? BIGINT(unixTime) : "";

      results.push_back(r);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
