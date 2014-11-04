// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include "osquery/database.h"

using std::string;
using boost::lexical_cast;

namespace osquery {
namespace tables {

QueryData genSuidBin() {
  Row r;
  QueryData results;
  struct stat info;

  boost::filesystem::recursive_directory_iterator it =
      boost::filesystem::recursive_directory_iterator(
          boost::filesystem::path("/"));
  boost::filesystem::recursive_directory_iterator end;

  while (it != end) {
    boost::filesystem::path path = *it;
    try {
      if (boost::filesystem::is_regular_file(path) &&
          ((it.status().permissions() & 04000) == 04000 ||
           (it.status().permissions() & 02000) == 02000)) {
        // store path
        r["path"] = boost::lexical_cast<std::string>(path);

        // store user and group
        if (stat(path.c_str(), &info) == 0) {
          struct passwd *pw = getpwuid(info.st_uid);
          struct group *gr = getgrgid(info.st_gid);
          // get user name
          r["unix_user"] = pw ? boost::lexical_cast<std::string>(pw->pw_name)
                              : boost::lexical_cast<std::string>(info.st_uid);
          // get group
          r["unix_group"] = gr ? boost::lexical_cast<std::string>(gr->gr_name)
                               : boost::lexical_cast<std::string>(info.st_gid);

          // get permission
          r["permissions"] = "";
          r["permissions"] +=
              (it.status().permissions() & 04000) == 04000 ? "S" : "";
          r["permissions"] +=
              (it.status().permissions() & 02000) == 02000 ? "G" : "";

          results.push_back(r);
        }
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
