// Copyright 2004-present Facebook. All Rights Reserved.

#include <set>
#include <mutex>
#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

#include <grp.h>

namespace osquery {
namespace tables {

std::mutex grpEnumerationMutex;

QueryData genGroups() {
  std::lock_guard<std::mutex> lock(grpEnumerationMutex);
  QueryData results;
  struct group *grp = nullptr;
  std::set<long> groups_in;

  setgrent();
  while ((grp = getgrent()) != NULL) {
    if (std::find(groups_in.begin(), groups_in.end(), grp->gr_gid) == groups_in.end()) {
      Row r;
      r["gid"] = boost::lexical_cast<std::string>(grp->gr_gid);
      r["name"] = std::string(grp->gr_name);
      results.push_back(r);
      groups_in.insert(grp->gr_gid);
    }
  }
  endgrent();
  groups_in.clear();

  return results;
}
}
}
