/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genEventLogs(QueryContext& context) {
  QueryData results;

  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  Row r;
  r["timestamp"] = BIGINT(filetimeToUnixtime(cTime));
  r["name"] = "Mock windows event";
  results.push_back(r);

  return results;
}
}
}
