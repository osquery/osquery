// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/filesystem.hpp>

#include "osquery/tables.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData genFile(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;

    Row r;
    r["path"] = path.string();
    r["filename"] = path.filename().string();
    r["is_file"] = INTEGER(boost::filesystem::is_regular_file(path));
    r["is_dir"] = INTEGER(boost::filesystem::is_directory(path));
    r["is_link"] = INTEGER(boost::filesystem::is_symlink(path));

    results.push_back(r);
  }

  return results;
}
}
}
