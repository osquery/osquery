// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/tables.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kXattrQuarantine = "com.apple.quarantine";

Status genQuarantineFile(const fs::path &path, QueryData &results) {
  int bufferLength =
      getxattr(path.string().c_str(), kXattrQuarantine.c_str(), NULL, 0, 0, 0);
  if (bufferLength <= 0) {
    return Status(1, "Failed to getxattr.");
  }

  char *value = (char *)malloc(sizeof(char *) * bufferLength);
  getxattr(path.string().c_str(),
           kXattrQuarantine.c_str(),
           value,
           bufferLength,
           0,
           0);

  std::vector<std::string> values;
  boost::split(values, value, boost::is_any_of(";"));
  boost::trim(values[2]);
  free(value);

  Row r;
  r["path"] = path.string();
  r["creator"] = values[2];
  results.push_back(r);

  return Status(0, "OK");
}

QueryData genQuarantine(QueryContext &context) {
  QueryData results;

  auto it = fs::recursive_directory_iterator(fs::path("/"));
  fs::recursive_directory_iterator end;

  while (it != end) {
    fs::path path = *it;

    genQuarantineFile(path, results);

    try {
      ++it;
    } catch (const fs::filesystem_error &ex) {
      VLOG(2) << "Permissions error on " << path.string();
      it.no_push();
    }
  }

  return results;
}
}
}
