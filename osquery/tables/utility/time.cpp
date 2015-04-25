/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ctime>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genTime(QueryContext& context) {
  Row r;
  time_t _time = time(0);
  struct tm* now = localtime(&_time);
  r["hour"] = INTEGER(now->tm_hour);
  r["minutes"] = INTEGER(now->tm_min);
  r["seconds"] = INTEGER(now->tm_sec);
  QueryData results;
  results.push_back(r);
  return results;
}
}
}
