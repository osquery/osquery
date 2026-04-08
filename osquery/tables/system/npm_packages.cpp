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
#include <sys/stat.h>
#include <unordered_set>
#include <utility>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>
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
    "C:\\Users\\%\\AppData\\Roaming\\npm",
    "C:\\Users\\%\\AppData\\Local\\nvm\\%"
#else
    "/usr/local/lib",
    "/opt/homebrew/lib",
    "/usr/lib",
    "/home/%/.npm-global/lib",
    "/home/%/.nvm/versions/node/%/lib",
    "/Users/%/.npm-global/lib",
    "/Users/%/.nvm/versions/node/%/lib"
#endif
};

const std::vector<std::string> kPackageKeys{
    "name", "version", "description", "homepage"};

const std::string kWinNodeInstallKey = "SOFTWARE\\Node.js\\InstallPath";

const int kDefaultMaxDepth = 100;

/**
 * @brief Check if a directory has already been visited using inode tracking.
 *
 * This prevents infinite loops from symlinks pointing back up the directory
 * tree. Uses platformLstat which doesn't follow symlinks.
 *
 * @param visited_inos Set of already-visited inodes
 * @param path Directory path to check
 * @return true if already visited, false if new
 */
static bool isDirVisited(std::unordered_set<int>& visited_inos,
                         const std::string& path) {
  if (path.empty()) {
    return true;
  }

  struct stat d_stat;
  if (!platformLstat(path, d_stat).ok()) {
    return false;
  }

  auto [_, inserted] = visited_inos.emplace(d_stat.st_ino);
  return !inserted;
}

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
                            Logger& logger,
                            int max_depth) {
  // Queue of (directory_to_search, current_depth) pairs
  std::vector<std::pair<std::string, int>> dirs_to_search;
  std::unordered_set<int> visited_inos;

  dirs_to_search.emplace_back(site, 0);

  while (!dirs_to_search.empty()) {
    auto [current_dir, depth] = dirs_to_search.back();
    dirs_to_search.pop_back();

    // Skip if we've visited this directory already (symlink loop protection)
    if (isDirVisited(visited_inos, current_dir)) {
      continue;
    }

    std::vector<std::string> manifest_paths;

    // Search for direct packages: node_modules/package/package.json
    fs::path pattern1("node_modules/%/package.json");
    resolveFilePattern(current_dir / pattern1, manifest_paths);

    // Search for scoped packages: node_modules/@scope/package/package.json
    fs::path pattern2("node_modules/@%/%/package.json");
    resolveFilePattern(current_dir / pattern2, manifest_paths);

    for (const auto& path : manifest_paths) {
      Row r;
      genNodePackage(path, r, logger);
      r["directory"] = site;
      r["path"] = path;
      r["depth"] = INTEGER(depth);
      r["max_depth"] = INTEGER(max_depth);
      r["pid_with_namespace"] = "0";
      results.push_back(r);

      // Queue nested node_modules for searching if not at max depth
      if (max_depth == -1 || depth < max_depth) {
        fs::path pkg_dir = fs::path(path).parent_path();
        fs::path nested_modules = pkg_dir / "node_modules";
        boost::system::error_code ec;
        if (fs::is_directory(nested_modules, ec)) {
          dirs_to_search.emplace_back(pkg_dir.string(), depth + 1);
        }
      }
    }
  }
}

void genWinNodePackages(const std::string& keyGlob,
                        QueryData& results,
                        Logger& logger,
                        int max_depth) {
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
      genNodeSiteDirectories(p.at("data"), results, logger, max_depth);
    }
    nodeInstallLocation.clear();
  }
#endif
}

QueryData genNodePackagesImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  std::set<std::string> paths;

  // Read max_depth constraint, default to kDefaultMaxDepth (100)
  int max_depth = kDefaultMaxDepth;
  if (context.constraints.count("max_depth") > 0 &&
      context.constraints.at("max_depth").exists(EQUALS)) {
    auto max_depth_set = context.constraints["max_depth"].getAll(EQUALS);
    if (!max_depth_set.empty()) {
      max_depth = tryTo<int>(*max_depth_set.begin()).takeOr(kDefaultMaxDepth);
    }
  }

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
      genWinNodePackages(installPathKey, results, logger, max_depth);

      // Enumerate any user installed npm packages
      installPathKey = "HKEY_USERS\\%\\" + kWinNodeInstallKey;
      genWinNodePackages(installPathKey, results, logger, max_depth);
    }
  }
  for (const auto& key : paths) {
    genNodeSiteDirectories(key, results, logger, max_depth);
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
