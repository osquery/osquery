// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include "osquery/database.h"

namespace osquery {
namespace tables {

const int kNumCols = 1;

QueryData genTime() {
  Row r;
  time_t _time = time(0);
  struct tm* now = localtime(&_time);
  r["hour"] = INTEGER(now->tm_hour);
  r["minutes"] = INTEGER(now->tm_min);
  r["seconds"] = INTEGER(now->tm_sec);
  QueryData results;
  for (int i = 0; i < kNumCols; ++i) {
    results.push_back(r);
  }
  return results;
}
}
}
