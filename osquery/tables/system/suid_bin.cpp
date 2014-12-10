// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

#include <boost/filesystem.hpp>
#include <boost/system/system_error.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

std::vector<std::string> kBinarySearchPaths = {
  "/bin",
  "/sbin",
  "/usr/bin",
  "/usr/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  "/tmp"
};

Status genBin(const fs::path& path, int perms, QueryData& results) {
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

bool isSuidBin(const fs::path& path, int perms) {
  if (!fs::is_regular_file(path)) {
    return false;
  }

  if ((perms & 04000) == 04000 || (perms & 02000) == 02000) {
    return true;
  }
  return false;
}

QueryData genSuidBinsFromPath(const std::string& path, QueryData& results) {
  auto it = fs::recursive_directory_iterator(fs::path(path));
  auto end = fs::recursive_directory_iterator();
  for (; it != end; ++it) {
    try {
      fs::path path = *it;
      int perms = path.status().permissions();
      if (isSuidBin(path, perms)) {
        genBin(path, parms, results);
      }
    } catch (fs::filesystem_error& e) {
      VLOG(1) << "Cannot read binary from " << path;
      it.no_push();
    }
  }

}

QueryData genSuidBin(QueryContext& context) {
  QueryData results;

  for (const auto& path : kBinarySearchPaths) {
    genSuidBinsFromPath(path, results);
  }

  return results;
}
}
}
