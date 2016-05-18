/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <glob.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {

boost::optional<std::string> getHomeDirectory() {
  // Try to get the caller's home directory using HOME and getpwuid.
  auto user = getpwuid(getuid());
  if (getenv("HOME") != nullptr) {
    return std::string(getenv("HOME"));
  }
  else if (user != nullptr && user->pw_dir != nullptr) {
    return std::string(user->pw_dir);
  } else {
    return boost::none;
  }
}

bool platformChmod(const std::string& path, mode_t perms) {
  return (chmod(path.c_str(), perms) == 0);
}

std::vector<std::string> platformGlob(std::string find_path) {
  std::vector<std::string> results;
  
  glob_t data;
  glob(path.c_str(), GLOB_TILDE | GLOB_MARK | GLOB_BRACE, nullptr, &data);
  size_t count = data.gl_pathc;
  
  for (size_t index = 0; index < count; index++) {
    results.push_back(data.gl_pathv[index]);
  }

  globfree(&data);
  return results;
}

int platformAccess(const std::string& path, int mode) {
  return access(path.c_str(), mode);
}
}