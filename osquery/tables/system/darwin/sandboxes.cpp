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

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

#define DECLARE_TABLE_IMPLEMENTATION_sandboxes
#include <generated/tables/tbl_sandboxes_defs.hpp>

namespace osquery {
namespace tables {

const std::vector<std::string> kSandboxContainerPaths = {
    "/Library/Containers/",
};

void genSandboxContainer(const fs::path& container, QueryData& results) {
  pt::ptree tree;
  fs::path path = container / "Container.plist";
  if (!pathExists(path.string()).ok() || !isReadable(path.string()).ok()) {
    // Container directory does not contain container details.
    return;
  }

  if (!osquery::parsePlist(path.string(), tree).ok()) {
    // Could not parse the container plist.
    return;
  }

  if (tree.count("SandboxProfileDataValidationInfo") == 0) {
    return;
  }

  auto& info = tree.get_child("SandboxProfileDataValidationInfo");
  if (info.count("SandboxProfileDataValidationParametersKey") == 0) {
    return;
  }

  Row r;
  auto& key_info = info.get_child("SandboxProfileDataValidationParametersKey");
  r["label"] = key_info.get("application_container_id", "");
  r["user"] = key_info.get("_USER", "");
  r["enabled"] = INTEGER(tree.get(
      "SandboxProfileDataValidationEntitlementsKey.com.apple.security.app-"
      "sandbox",
      0));
  r["build_id"] = key_info.get("sandbox_build_id", "");
  r["bundle_path"] = key_info.get("application_bundle", "");
  r["path"] = container.string();
  results.push_back(r);
}

QueryData genSandboxContainers(QueryContext& context) {
  QueryData results;

  // Get the login items available in System Preferences for each user.
  for (const auto& dir : getHomeDirectories()) {
    for (const auto& path : kSandboxContainerPaths) {
      std::vector<std::string> containers;
      osquery::listDirectoriesInDirectory(dir / path, containers);
      for (const auto& container : containers) {
        genSandboxContainer(container, results);
      }
    }
  }

  return results;
}
}
}
