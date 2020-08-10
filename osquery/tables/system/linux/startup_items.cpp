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

namespace osquery {
namespace tables {

const std::vector<std::string> kSystemItemPaths = {"/etc/xdg/autostart/"};

const std::vector<std::string> kSystemScriptPaths = {"/etc/init.d/"};

void genAutoStartItems(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    std::string content;
    if (readFile(file, content)) {
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
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

void genAutoStartScripts(const std::string& sysdir, QueryData& results) {
  std::vector<std::string> dirFiles;
  auto s = osquery::listFilesInDirectory(sysdir, dirFiles, false);
  if (!s.ok()) {
    VLOG(1) << "Error traversing " << sysdir << ": " << s.what();
  }
  for (const auto& file : dirFiles) {
    Row r;
    r["name"] = osquery::split(file, "/").back();
    r["path"] = file;
    r["type"] = "Startup Item";
    r["status"] = "enabled";
    r["source"] = sysdir;
    auto username = osquery::split(sysdir, "/");
    if (username.size() > 1 && username[0] == "home") {
      r["username"] = username[1];
    }
    results.push_back(r);
  }
}

QueryData genStartupItems(QueryContext& context) {
  QueryData results;

  // User specific
  for (const auto& dir : getHomeDirectories()) {
    auto itemsDir = dir / "/.config/autostart/";
    auto scriptsDir = dir / "/.config/autostart-scripts/";
    genAutoStartItems(itemsDir.string(), results);
    genAutoStartScripts(scriptsDir.string(), results);
  }

  // System specific
  for (const auto& dir : kSystemScriptPaths) {
    genAutoStartScripts(dir, results);
  }
  for (const auto& dir : kSystemItemPaths) {
    genAutoStartItems(dir, results);
  }

  return results;
}

} // namespace tables
} // namespace osquery
