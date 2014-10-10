// Copyright 2004-present Facebook. All Rights Reserved.

#include <set>
#include <vector>
#include <string>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

#include <pwd.h>

namespace osquery {
namespace tables {

QueryData genUsers() {
  QueryData results;
  struct passwd *pwd = nullptr;
  std::set<long> users_in;

  while ((pwd = getpwent()) != NULL) {
    if (std::find(users_in.begin(), users_in.end(), pwd->pw_uid) == users_in.end()) {
      Row r;
      r["uid"] = boost::lexical_cast<std::string>(pwd->pw_uid);
      r["gid"] = boost::lexical_cast<std::string>(pwd->pw_gid);
      r["username"] = std::string(pwd->pw_name);
      r["description"] = std::string(pwd->pw_gecos);
      r["directory"] = std::string(pwd->pw_dir);
      r["shell"] = std::string(pwd->pw_shell);
      results.push_back(r);
      users_in.insert(pwd->pw_uid);
    }
  }
  endpwent();
  users_in.clear();

  return results;
}
}
}
