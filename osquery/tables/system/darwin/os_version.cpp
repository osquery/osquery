/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  auto sysctl =
      SQL::selectAllFrom("system_controls", "name", EQUALS, "kern.osrelease");
  if (sysctl.size() == 0) {
    return {};
  }

  auto version = osquery::split(sysctl[0].at("current_value"), ".");
  Row r;
  r["major"] = INTEGER(version[0]);
  r["minor"] = INTEGER(version[1]);
  r["patch"] = INTEGER(version[2]);
  return {r};
}
}
}
