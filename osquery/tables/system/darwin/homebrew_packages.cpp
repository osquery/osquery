/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::set<std::string> kHomebrewPrefixes = {
    "/usr/local",
    "/opt/homebrew",
};

std::vector<std::string> getHomebrewAppInfoPlistPaths(const std::string& root) {
  std::vector<std::string> results;
  auto status = osquery::listDirectoriesInDirectory(root, results);
  if (!status.ok()) {
    TLOG << "Error listing " << root << ": " << status.toString();
  }

  return results;
}

std::string getHomebrewNameFromInfoPlistPath(const std::string& path) {
  auto bits = osquery::split(path, "/");
  return bits[bits.size() - 1];
}

std::vector<std::string> getHomebrewVersionsFromInfoPlistPath(
    const std::string& path) {
  std::vector<std::string> results;
  std::vector<std::string> app_versions;
  auto status = osquery::listDirectoriesInDirectory(path, app_versions);
  if (status.ok()) {
    for (const auto& version : app_versions) {
      results.push_back(fs::path(version).parent_path().filename().string());
    }
  } else {
    TLOG << "Error listing " << path << ": " << status.toString();
  }

  return results;
}

void packagesFromPrefix(QueryData& results,
                        const std::string& prefix,
                        bool userRequested) {
  // The Homebrew wrapper script finds the Library directory by taking the
  // directory that it is located in and concatenating `/../Library`:
  //   BREW_FILE_DIRECTORY=$(chdir "${0%/*}" && pwd -P)
  //   export HOMEBREW_BREW_FILE="$BREW_FILE_DIRECTORY/${0##*/}"
  // Note that the `-P` flag to pwd resolves all symlinks.
  //
  // Next, it will use given filename to find the prefix:
  //   HOMEBREW_PREFIX = Pathname.new(HOMEBREW_BREW_FILE).dirname.parent

  if (!pathExists(prefix).ok()) {
    if (userRequested) {
      LOG(WARNING) << "Error reading homebrew prefix " << prefix;
    }
    return;
  }

  auto cellarPath = fs::path(prefix) / "Cellar";

  if (!pathExists(cellarPath).ok()) {
    if (userRequested) {
      LOG(WARNING) << "Error reading homebrew cellar path "
                   << cellarPath.native();
    }
    return;
  }

  for (const auto& path :
       getHomebrewAppInfoPlistPaths(fs::canonical(cellarPath).string())) {
    auto versions = getHomebrewVersionsFromInfoPlistPath(path);
    auto name = getHomebrewNameFromInfoPlistPath(path);
    for (const auto& version : versions) {
      // Support a many to one version to package name.
      Row r;
      r["name"] = name;
      r["path"] = path;
      r["version"] = version;
      r["prefix"] = prefix;

      results.push_back(r);
    }
  }
}

QueryData genHomebrewPackages(QueryContext& context) {
  QueryData results;

  if (context.constraints.count("prefix") > 0 &&
      context.constraints.at("prefix").exists(EQUALS)) {
    std::set<std::string> prefixes =
        context.constraints["prefix"].getAll(EQUALS);
    for (const auto& prefix : prefixes) {
      packagesFromPrefix(results, prefix, true);
    }
  } else {
    // No prefixes requested, fall back to the system ones.
    for (const auto& prefix : kHomebrewPrefixes) {
      packagesFromPrefix(results, prefix, false);
    }
  }
  return results;
}
}
}
