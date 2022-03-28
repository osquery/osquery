/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <stdlib.h>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/json/json.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

#ifdef WIN32
#include "windows/registry.h"
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::set<std::string> kNodeModulesPath = {
#ifdef WIN32
    "C:\\Users\\%\\AppData\\Roaming\\npm"
#else
    "/usr/local/lib",
    "/opt/homebrew/lib",
    "/usr/lib",
    "/home/%/.npm-global/lib",
    "/Users/%/.npm-global/lib"
#endif
};

const std::vector<std::string> kPackageKeys{
    "name", "version", "description", "homepage"};

const std::string kWinNodeInstallKey = "SOFTWARE\\Node.js\\InstallPath";

void genNodePackage(const std::string& file, Row& r, Logger& logger) {
  std::string json;

  if (!readFile(file, json).ok()) {
    logger.vlog(1, "Could not read package.json from: " + file);
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    logger.vlog(1, "Could not parse package.json from: " + file);
    return;
  }

  // create row from json and add it to results
  for (const auto& key : kPackageKeys) {
    if (doc.doc().HasMember(key)) {
      const auto& value = doc.doc()[key];
      r[key] = (value.IsString()) ? value.GetString() : "";
    }
  }

  // Manually get nested key (Author name)
  if (doc.doc().HasMember("author")) {
    const auto& author = doc.doc()["author"];
    if (author.IsString()) {
      r["author"] = author.GetString();
    } else if (author.IsObject()) {
      if (author.HasMember("name")) {
        const auto& author_name = author["name"];
        r["author"] = (author_name.IsString()) ? author_name.GetString() : "";
      }
    }
  }

  // Manually get license to support deprecated licence schema.
  // In the current schema it is a string, but in previous versions it is a
  // dictionary with url and type
  if (doc.doc().HasMember("license")) {
    const auto& license = doc.doc()["license"];
    if (license.IsString()) {
      // Current license schema is just a top level string
      r["license"] = license.GetString();
    } else {
      // If its not a string, is it a dict with 'url' ?
      if (license.HasMember("url")) {
        const auto& license_url = license["url"];
        if (license_url.IsString()) {
          // Fallback to displaying deprecated licence url
          r["license"] = license_url.GetString();
        }
      }
    }
  }
}

void genNodeSiteDirectories(const std::string& site,
                            QueryData& results,
                            Logger& logger) {
  std::vector<std::string> manifest_paths;
  boost::filesystem::path pattern("node_modules/%/package.json");
  resolveFilePattern(site / pattern, manifest_paths);

  for (const auto& path : manifest_paths) {
    Row r;
    genNodePackage(path, r, logger);
    r["directory"] = site;
    r["path"] = path;
    r["pid_with_namespace"] = "0";
    results.push_back(r);
  }
}

void genWinNodePackages(const std::string& keyGlob,
                        QueryData& results,
                        Logger& logger) {
#ifdef WIN32
  std::set<std::string> installPathKeys;
  expandRegistryGlobs(keyGlob, installPathKeys);
  QueryData nodeInstallLocation;
  for (const auto& installKey : installPathKeys) {
    queryKey(installKey, nodeInstallLocation);
    for (const auto& p : nodeInstallLocation) {
      if (p.at("name") != "(Default)") {
        continue;
      }
      genNodeSiteDirectories(p.at("data"), results, logger);
    }
    nodeInstallLocation.clear();
  }
#endif
}

QueryData genNodePackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::set<std::string> paths;
  if (context.constraints.count("directory") > 0 &&
      context.constraints.at("directory").exists(EQUALS)) {
    paths = context.constraints["directory"].getAll(EQUALS);
  } else {
    for (const auto& path : kNodeModulesPath) {
      std::vector<std::string> sites;
      resolveFilePattern(path, sites);
      for (const auto& site : sites) {
        paths.insert(site);
      }
    }
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      // Enumerate any system installed npm packages
      auto installPathKey = "HKEY_LOCAL_MACHINE\\" + kWinNodeInstallKey;
      genWinNodePackages(installPathKey, results, logger);

      // Enumerate any user installed npm packages
      installPathKey = "HKEY_USERS\\%\\" + kWinNodeInstallKey;
      genWinNodePackages(installPathKey, results, logger);
    }
  }
  for (const auto& key : paths) {
    genNodeSiteDirectories(key, results, logger);
  }

  return results;
}

QueryData genNodePackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "npm_packages", genNodePackagesImpl);
  } else {
    GLOGLogger logger;
    return genNodePackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
