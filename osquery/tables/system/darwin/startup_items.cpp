/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::vector<std::string> kLibraryStartupItemPaths = {
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
};

void genLibraryStartupItems(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      if (!fs::exists(it->status()) || !fs::is_directory(it->status())) {
        continue;
      }

      Row r;
      r["name"] = it->path().string();
      r["path"] = it->path().string();
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      r["source"] = sysdir;
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // Find system wide startup items in Library directories.
  for (const auto& dir : kLibraryStartupItemPaths) {
    genLibraryStartupItems(dir, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
