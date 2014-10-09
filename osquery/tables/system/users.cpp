// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <pwd.h>

#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genUsers() {
  QueryData results;
  struct passwd *pwd = (passwd *)malloc(sizeof(struct passwd));

  setpwent();
  while ((pwd = getpwent()) != NULL) {
    Row r;
    r["uid"] = boost::lexical_cast<std::string>(pwd->pw_uid);
    r["gid"] = boost::lexical_cast<std::string>(pwd->pw_gid);
    r["username"] = std::string(pwd->pw_name);
    r["description"] = std::string(pwd->pw_gecos);
    r["directory"] = std::string(pwd->pw_dir);
    r["shell"] = std::string(pwd->pw_shell);

    results.push_back(r);
  }
  endpwent();
  free(pwd);

  return results;
}
}
}
