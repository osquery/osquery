/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <boost/filesystem.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/process.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

Status genPackage(fs::path nuspec, Row& r) {
  std::string content;
  if (!readFile(nuspec, content).ok()) {
    return Status(1, "Failed to read nuspec:" + nuspec.string());
  }

  std::stringstream ss;
  ss << content;
  pt::ptree propTree;
  read_xml(ss, propTree);

  r["name"] = propTree.get("package.metadata.id", "");
  r["version"] = propTree.get("package.metadata.version", "");
  r["summary"] = propTree.get("package.metadata.summary", "");
  r["author"] = propTree.get("package.metadata.authors", "");
  r["license"] = propTree.get("package.metadata.licenseUrl", "");
  r["path"] = nuspec.string();

  return Status();
}

QueryData genChocolateyPackages(QueryContext& context) {
  QueryData results;

  auto chocoEnvInstall = getEnvVar("ChocolateyInstall");

  fs::path chocoInstallPath;
  if (chocoEnvInstall.is_initialized()) {
    chocoInstallPath = fs::path(*chocoEnvInstall);
  }

  if (chocoInstallPath.empty()) {
    LOG(WARNING) << "Did not find chocolatey path environment variable.";
    return results;
  }

  auto nuspecPattern = chocoInstallPath / "lib/%/%.nuspec";
  std::vector<std::string> manifests;
  resolveFilePattern(nuspecPattern, manifests, GLOB_FILES);

  for (const auto& pkg : manifests) {
    Row r;
    auto s = genPackage(pkg, r);
    if (!s.ok()) {
      VLOG(1) << "Failed to parse " << pkg << " with " << s.getMessage();
    }
    results.push_back(r);
  }

  return results;
}
}
}
