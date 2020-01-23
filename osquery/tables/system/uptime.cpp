/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/tables.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
namespace tables {

QueryData genUptime(QueryContext& context) {
  Row r;
  QueryData results;
  long uptime_in_seconds = getUptime();

  if (uptime_in_seconds >= 0) {
    r["days"] = INTEGER(uptime_in_seconds / 60 / 60 / 24);
    r["hours"] = INTEGER((uptime_in_seconds / 60 / 60) % 24);
    r["minutes"] = INTEGER((uptime_in_seconds / 60) % 60);
    r["seconds"] = INTEGER(uptime_in_seconds % 60);
    r["total_seconds"] = BIGINT(uptime_in_seconds);
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
