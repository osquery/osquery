// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <utmpx.h>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genLastAccess() {
  QueryData results;
  struct utmpx *ut;
#ifdef __APPLE__
  setutxent_wtmp(0); // 0 = reverse chronological order

  while ((ut = getutxent_wtmp()) != NULL) {
#else

  utmpxname("/var/log/wtmpx");
  setutxent();

  while ((ut = getutxent()) != NULL) {
#endif

    Row r;
    r["username"] = std::string(ut->ut_user);
    r["tty"] = std::string(ut->ut_line);
    r["pid"] = boost::lexical_cast<std::string>(ut->ut_pid);
    r["type"] = boost::lexical_cast<std::string>(ut->ut_type);
    r["time"] = boost::lexical_cast<std::string>(ut->ut_tv.tv_sec);
    r["host"] = std::string(ut->ut_host);

    results.push_back(r);
  }

#ifdef __APPLE__
  endutxent_wtmp();
#else
  endutxent();
#endif

  return results;
}
}
}
