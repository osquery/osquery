/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <stdlib.h>
#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#ifdef WIN32
#include "osquery/tables/system/windows/registry.h"
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Number of fields when splitting metadata and info.
const size_t kNumFields = 2;
const std::set<std::string> kPythonPath = {
    "/usr/local/lib/python2.7/dist-packages/",
    "/usr/local/lib/python2.7/site-packages/",
    "/usr/lib/python2.7/dist-packages/",
    "/usr/lib/python2.7/site-packages/",
    "/Library/Python/2.7/site-packages/",
    };

const std::set<std::string> kDarwinPythonPath = {
    "/System/Library/Frameworks/Python.framework/Versions/",
};

const std::string kWinPythonInstallKey =
    "SOFTWARE\\Python\\PythonCore\\%\\InstallPath";

void genPackage(const std::string& path, Row& r) {
  std::string content;
  if (!readFile(path, content).ok()) {
    TLOG << "Cannot find info file: " << path;
    return;
  }


  auto lines = split(content, "\n");

  for (const auto& line : lines) {
    auto fields = split(line, ":");

    if (fields.size() != kNumFields) {
      continue;
    }

    if (fields[0] == "Name") {
      r["name"] = fields[1];
    } else if (fields[0] == "Version") {
      r["version"] = fields[1];
    } else if (fields[0] == "Summary") {
      r["summary"] = fields[1];
    } else if (fields[0] == "Author") {
      r["author"] = fields[1];
    } else if (fields[0] == "License") {
      r["license"] = fields[1];
      break;
    }
  }
}

void genSiteDirectories(const std::string& site, QueryData& results) {
  std::vector<std::string> directories;
  if (!listDirectoriesInDirectory(site, directories, true).ok()) {
    return;
  }

  for (const auto& directory : directories) {
    if (!isDirectory(directory).ok()) {
      continue;
    }

    Row r;
    if (directory.find(".dist-info") != std::string::npos) {
      auto path = directory + "/METADATA";
      genPackage(path, r);
    } else if (directory.find(".egg-info") != std::string::npos) {
      auto path = directory + "PKG-INFO";
      genPackage(path, r);
    } else {
      continue;
    }

    r["directory"]=site;
    r["path"] = directory;
    results.push_back(r);
  }
}

void genWinPythonPackages(const std::string& keyGlob, QueryData& results) {
#ifdef WIN32
  std::set<std::string> installPathKeys;
  expandRegistryGlobs(keyGlob, installPathKeys);
  QueryData pythonInstallLocation;
  for (const auto& installKey : installPathKeys) {
    queryKey(installKey, pythonInstallLocation);
    for (const auto& p : pythonInstallLocation) {
      if (p.at("name") != "(Default)") {
        continue;
      }
      genSiteDirectories(p.at("data"), results);
    }
    pythonInstallLocation.clear();
  }
#endif
}




QueryData genPythonPackages(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths;
  if (context.constraints.count("directory") > 0 &&
       context.constraints.at("directory").exists(EQUALS)) {
        paths = context.constraints["directory"].getAll(EQUALS);
         for (const auto& key: paths) {
          genSiteDirectories(key, results);
        }
  } else {
      for (const auto& key: kPythonPath) {
          genSiteDirectories(key, results);
          
      }
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    for (const auto& dir : kDarwinPythonPath) {
      std::vector<std::string> versions;
      if (!listDirectoriesInDirectory(dir, versions, false).ok()) {
        continue;
      }

      for (const auto& version : versions) {
        // macOS will link older versions to 2.6.
        auto version_path = fs::path(version).parent_path();
        if (fs::is_symlink(symlink_status(version_path))) {
          continue;
        }

        auto complete = version + "lib/python" +
                        version_path.filename().string() + "/site-packages/";
        genSiteDirectories(complete, results);
      }
    }
  } else if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Enumerate any system installed python packages
    auto installPathKey = "HKEY_LOCAL_MACHINE\\" + kWinPythonInstallKey;
    genWinPythonPackages(installPathKey, results);

    // Enumerate any user installed python packages
    installPathKey = "HKEY_USERS\\%\\" + kWinPythonInstallKey;
    genWinPythonPackages(installPathKey, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
