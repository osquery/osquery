/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreServices/CoreServices.h>
#include <Foundation/Foundation.h>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/darwin/plist.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kSysExtDBPath = "/Library/SystemExtensions/db.plist";

std::string getExtensionCategory(const pt::ptree& ptree) {
  std::vector<std::string> categories;
  for (const auto& item : ptree) {
    categories.push_back(item.second.get("", ""));
  }
  return boost::algorithm::join(categories, ", ");
}

void getExtensionRow(const pt::ptree& extension, Row& r) {
  r["path"] = extension.get("originPath", "");
  r["UUID"] = extension.get("uniqueID", "");
  r["state"] = extension.get("state", "");
  r["identifier"] = extension.get("identifier", "");
  r["version"] = extension.get("bundleVersion.CFBundleShortVersionString", "");
  r["team"] = extension.get("teamID", "");

  // Get the system extension categories from the array
  const auto category = extension.get_child("categories");
  r["category"] = getExtensionCategory(category);
  r["bundle_path"] = extension.get("container.bundlePath", "");
}

QueryData genExtensionsFromPtree(const pt::ptree& ptree) {
  QueryData results;
  const auto extensions_attr_opt = ptree.get_child_optional("extensions");
  if (!extensions_attr_opt.has_value()) {
    return results;
  }

  const auto& extensions_attr = extensions_attr_opt.value();
  for (const auto& array_entry : extensions_attr) {
    const auto& extension_value = array_entry.second;
    Row r;
    getExtensionRow(extension_value, r);
    results.push_back(r);
  }
  return results;
}

QueryData genSystemExtensions(QueryContext& context) {
  if (!osquery::pathExists(kSysExtDBPath)) {
    VLOG(1) << "System extension database does not exist: " << kSysExtDBPath;
    return {};
  }

  pt::ptree ptree;
  if (!osquery::parsePlist(kSysExtDBPath, ptree).ok()) {
    LOG(ERROR) << "Failed to parse: " << kSysExtDBPath;
    return {};
  }

  return genExtensionsFromPtree(ptree);
}
}
}
