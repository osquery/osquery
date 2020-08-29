/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/filesystem/filesystem.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

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

  return Status::success();
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
