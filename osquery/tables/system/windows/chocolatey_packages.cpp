/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/process.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

#define DECLARE_TABLE_IMPLEMENTATION_chocolatey_packages
#include <generated/tables/tbl_chocolatey_packages_defs.hpp>

namespace osquery {
namespace tables {

Status genPackage(const fs::path& nuspec, Row& r) {
  r["path"] = nuspec.string();
  pt::ptree propTree;

  {
    std::string content;
    if (!readFile(nuspec, content).ok()) {
      return Status(1, "Failed to read nuspec:" + nuspec.string());
    }

    std::stringstream ss;
    ss << content;
    try {
      read_xml(ss, propTree);
    } catch (const pt::xml_parser::xml_parser_error& /* e */) {
      return Status(1, "Failed to parse nuspec xml");
    }
  }

  r["name"] = propTree.get("package.metadata.id", "");
  r["version"] = propTree.get("package.metadata.version", "");
  r["summary"] = propTree.get("package.metadata.summary", "");
  r["author"] = propTree.get("package.metadata.authors", "");
  r["license"] = propTree.get("package.metadata.licenseUrl", "");

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
    LOG(WARNING) << "Did not find chocolatey path environment variable";
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
