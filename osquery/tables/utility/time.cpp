// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <boost/lexical_cast.hpp>

#include "osquery/database.h"

namespace osquery {
namespace tables {

const int kNumCols = 1;

QueryData genTime() {
  Row r;
  time_t _time = time(0);
  struct tm* now = localtime(&_time);
  r["hour"] = boost::lexical_cast<std::string>(now->tm_hour);
  r["minutes"] = boost::lexical_cast<std::string>(now->tm_min);
  r["seconds"] = boost::lexical_cast<std::string>(now->tm_sec);
  QueryData results;
  for (int i = 0; i < kNumCols; ++i) {
    results.push_back(r);
  }
  return results;
}
}
}
