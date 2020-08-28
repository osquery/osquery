/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

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
