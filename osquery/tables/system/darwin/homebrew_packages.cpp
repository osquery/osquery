/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kHomebrewBinary {"/usr/local/bin/brew"};

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

Status getHomebrewCellar(fs::path& cellarPath) {
  // The Homebrew wrapper script finds the Library directory by taking the
  // directory that it is located in and concatenating `/../Library`:
  //   BREW_FILE_DIRECTORY=$(chdir "${0%/*}" && pwd -P)
  //   export HOMEBREW_BREW_FILE="$BREW_FILE_DIRECTORY/${0##*/}"
  // Note that the `-P` flag to pwd resolves all symlinks.
  //
  // Next, it will use given filename to find the prefix:
  //   HOMEBREW_PREFIX = Pathname.new(HOMEBREW_BREW_FILE).dirname.parent

  if (!pathExists(kHomebrewBinary).ok()) {
    return Status(1, "No Homebrew binary found");
  }

  // Get the actual location of the Homebrew binary.
  // In the future, we could extend this to look at all 'brew' executables in
  // $PATH and check all of them.
  auto brewExecutable = fs::canonical(kHomebrewBinary);

  // Note that the first `parent_path` call is to remove the filename, and the
  // next to actually move up a directory.
  auto path = brewExecutable.parent_path().parent_path();
  // Newer versions of Homebrew may include a 'Homebrew' directory.
  if ("Homebrew" == path.leaf().string()) {
    path = path.parent_path();
  }

  path /= "Cellar";
  if (!pathExists(path).ok()) {
    return Status(1, "No Homebrew Cellar found");
  }

  cellarPath = path;
  return Status(0, "OK");
}

QueryData genHomebrewPackages(QueryContext& context) {
  QueryData results;
  fs::path cellar;

  auto status = getHomebrewCellar(cellar);
  if (!status.ok()) {
    TLOG << "Could not list Homebrew packages: " << status.toString();
    return results;
  }

  for (const auto& path : getHomebrewAppInfoPlistPaths(cellar.native())) {
    auto versions = getHomebrewVersionsFromInfoPlistPath(path);
    auto name = getHomebrewNameFromInfoPlistPath(path);
    for (const auto& version : versions) {
      // Support a many to one version to package name.
      Row r;
      r["name"] = name;
      r["path"] = path;
      r["version"] = version;

      results.push_back(r);
    }
  }
  return results;
}
}
}
