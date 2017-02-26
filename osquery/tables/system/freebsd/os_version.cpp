/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genOSVersion(QueryContext& context) {
  Row r;

  r["major"] = "10";
  r["minor"] = "2";
  r["patch"] = "";
  r["name"] = "";
  r["build"] = "RELEASE";
  return {r};
}

QueryData genSystemInfo(QueryContext& context) {
  return QueryData();
}

QueryData genPlatformInfo(QueryContext& context) {
  return QueryData();
}
}
}
