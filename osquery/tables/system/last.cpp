// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <utmpx.h>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

using namespace osquery::db;

namespace osquery {
namespace tables {

QueryData genLastAccess() {
  QueryData results;
  struct utmpx *ut;

  setutxent_wtmp(0); // 0 = reverse chronological order
  while ((ut = getutxent_wtmp()) != NULL) {
    Row r;
    r["login"] = std::string(ut->ut_user);
    r["tty"] = std::string(ut->ut_line);
    r["pid"] = boost::lexical_cast<std::string>(ut->ut_pid);
    r["type"] = boost::lexical_cast<std::string>(ut->ut_type);
    r["time"] = boost::lexical_cast<std::string>(ut->ut_tv.tv_sec);
    r["host"] = std::string(ut->ut_host);

    results.push_back(r);
  }
  endutxent_wtmp();

  return results;
}
}
}
