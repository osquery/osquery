/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

void genAutoStartItems(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      Row r;
      std::string content;
      if (readFile(it->path().string(), content)) {
        for (const auto& line : osquery::split(content, "\n")) {
          if (line.find("Name=") == 0) {
            auto details = osquery::split(line, "=");
            if (details.size() == 2) {
              r["name"] = details[1];
            }
          }
          if (line.find("Exec=") == 0) {
            auto details = osquery::split(line, "=");
            if (details.size() == 2) {
              r["path"] = details[1];
            }
          }
        }
      }
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      r["source"] = sysdir;

      auto username = osquery::split(sysdir, "/");
      if (username.size() > 1) {
        r["username"] = username[1];
      }
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

void genAutoStartScripts(const std::string& sysdir, QueryData& results) {
  try {
    fs::directory_iterator it((fs::path(sysdir))), end;
    for (; it != end; ++it) {
      Row r;
      auto name = osquery::split(it->path().string(), "/");
      r["name"] = name.back();
      r["path"] = it->path().string();
      r["type"] = "Startup Item";
      r["status"] = "enabled";
      r["source"] = sysdir;
      auto username = osquery::split(sysdir, "/");
      if (username.size() > 1) {
        r["username"] = username[1];
      }
      results.push_back(r);
    }
  } catch (const fs::filesystem_error& e) {
    VLOG(1) << "Error traversing " << sysdir << ": " << e.what();
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;
  // gen autostart
  // gen autostart scripts
  for (const auto& dir : getHomeDirectories()) {
    auto itemsDir = dir / "/.config/autostart/";
    auto scriptsDir = dir / "/.config/autostart-scripts/";
    genAutoStartItems(itemsDir.string(), results);
    genAutoStartScripts(scriptsDir.string(), results);
  }
  return results;
}

} // namespace tables
} // namespace osquery
