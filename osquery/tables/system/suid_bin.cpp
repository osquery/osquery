// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/system/system_error.hpp>

#include <glog/logging.h>

#include "osquery/database.h"

namespace osquery {
namespace tables {

Status genBin(const boost::filesystem::path &path,
              int perms,
              QueryData &results) {
  struct stat info;
  // store user and group
  if (stat(path.c_str(), &info) != 0) {
    return Status(1, "stat failed");
  }

  // store path
  Row r;
  r["path"] = path.string();

  struct passwd *pw = getpwuid(info.st_uid);
  struct group *gr = getgrgid(info.st_gid);

  // get user name + group
  std::string user;
  if (pw != nullptr) {
    user = std::string(pw->pw_name);
  } else {
    user = boost::lexical_cast<std::string>(info.st_uid);
  }

  std::string group;
  if (gr != nullptr) {
    group = std::string(gr->gr_name);
  } else {
    group = boost::lexical_cast<std::string>(info.st_gid);
  }

  r["username"] = user;
  r["groupname"] = group;

  r["permissions"] = "";
  if ((perms & 04000) == 04000) {
    r["permissions"] += "S";
  }

  if ((perms & 02000) == 02000) {
    r["permissions"] += "G";
  }

  results.push_back(r);
  return Status(0, "OK");
}

QueryData genSuidBin() {
  QueryData results;
  boost::system::error_code error;

#if defined(UBUNTU)
  // When building on supported Ubuntu systems, boost may ABRT.
  if (geteuid() != 0) {
    return results;
  }
#endif

  boost::filesystem::recursive_directory_iterator it =
      boost::filesystem::recursive_directory_iterator(
          boost::filesystem::path("/"), error);

  if (error.value() != boost::system::errc::success) {
    LOG(ERROR) << "Error opening \"/\": " << error.message();
    return results;
  }
  boost::filesystem::recursive_directory_iterator end;

  while (it != end) {
    boost::filesystem::path path = *it;
    try {
      int perms = it.status().permissions();
      if (boost::filesystem::is_regular_file(path) &&
          ((perms & 04000) == 04000 || (perms & 02000) == 02000)) {
        genBin(path, perms, results);
      }
    } catch (...) {
      // handle invalid files like /dev/fd/3
    }
    try {
      ++it;
    } catch (std::exception &ex) {
      it.no_push(); // handle permission error.
    }
  }

  return results;
}
}
}
