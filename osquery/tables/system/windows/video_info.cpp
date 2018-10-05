/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genVideoInfo(QueryContext& context) {
  Row r;
  QueryData results;

  const WmiRequest wmiSystemReq("SELECT * FROM Win32_VideoController");
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  if (wmiResults.empty()) {
    LOG(WARNING) << "Failed to retrieve video information";
    return {};
  } else {
    long bitsPerPixel = 0;
    wmiResults[0].GetLong("CurrentBitsPerPixel", bitsPerPixel);
    r["color_depth"] = INTEGER(bitsPerPixel);
    wmiResults[0].GetString("InstalledDisplayDrivers", r["driver"]);
    wmiResults[0].GetString("DriverDate", r["driver_date"]);
    wmiResults[0].GetString("DriverVersion", r["driver_version"]);
    wmiResults[0].GetString("AdapterCompatibility", r["manufacturer"]);
    wmiResults[0].GetString("VideoProcessor", r["model"]);
    wmiResults[0].GetString("Name", r["series"]);
    wmiResults[0].GetString("VideoModeDescription", r["video_mode"]);
  }

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
