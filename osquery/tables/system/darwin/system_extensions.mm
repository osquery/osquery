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

// com.apple.system-extension-policy payload defines the policy for
// the system extensions. The function looks for team identifier or
// extension bundle identifiers in the allowed list.
// https://developer.apple.com/documentation/devicemanagement/systemextensions?language=objc
uint32_t getPolicyFlag(const pt::ptree& ptree,
                       const std::string& teamid,
                       const std::string& identifier) {
  enum : uint32_t {
    POLICY_NONE = 0,
    POLICY_MANAGED = 1,
  };
  const auto& policies_attr_opt = ptree.get_child_optional("extensionPolicies");
  if (!policies_attr_opt.has_value()) {
    return POLICY_NONE;
  }

  const auto& policies_attr = policies_attr_opt.value();
  for (const auto& policy : policies_attr) {
    // Get the list of AllowedTeamIdentifiers that are valid and system
    // extensions signed by them are allowed to load.
    //
    // All system extensions signed with any of the specified team identifiers
    // will be considered to be approved
    const auto& policy_item = policy.second;

    // get the list of allowed team id's in extension policy tree and
    // look for the teamid in them
    const auto& allowed_team_opt =
        policy_item.get_child_optional("allowedTeamIDs");
    if (allowed_team_opt.has_value()) {
      const auto& allowed_team = allowed_team_opt.value();
      for (const auto& team : allowed_team) {
        if (team.second.get("", "") == teamid) {
          return POLICY_MANAGED;
        }
      }
    }

    // if the teamid is not in the allowedTeamID's list check for the
    // allowed system extensions.
    const auto& allowed_extensions_opt =
        policy_item.get_child_optional("allowedExtensions");
    // allowed system extension is empty
    if (!allowed_extensions_opt.has_value()) {
      return POLICY_NONE;
    }

    // Get the list of allowed extensions which is a dictionary of
    // extension list mapped with teamid
    const auto& allowed_extensions = allowed_extensions_opt.value();
    const auto& extensions_opt = allowed_extensions.get_child_optional(teamid);
    if (extensions_opt.has_value()) {
      const auto& extensions = extensions_opt.value();
      for (const auto& extension : extensions) {
        if (extension.second.get("", "") == identifier) {
          return POLICY_MANAGED;
        }
      }
    }
  }

  return POLICY_NONE;
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
  r["mdm_managed"] = INTEGER(0);
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
    Row row;
    getExtensionRow(extension_value, row);

    // get row teamid and identifier and lookup for them in the
    // extension policy
    auto row_teamid = row["team"];

    // teamid is required for the extension policy lookup. If teamid
    // is empty the policy flag will be set to default(`0`)
    if (!row_teamid.empty()) {
      auto row_identifier = row["identifier"];
      row["mdm_managed"] =
          INTEGER(getPolicyFlag(ptree, row_teamid, row_identifier));
    }

    // add row to the results
    results.push_back(row);
  }
  return results;
}

QueryData genSystemExtensions(QueryContext& context) {
  if (@available(macOS 10.15, *)) {
    if (!osquery::pathExists(kSysExtDBPath)) {
      LOG(WARNING) << "System extension database does not exist: "
                   << kSysExtDBPath;
      return {};
    }

    pt::ptree ptree;
    if (!osquery::parsePlist(kSysExtDBPath, ptree).ok()) {
      LOG(ERROR) << "Failed to parse: " << kSysExtDBPath;
      return {};
    }

    return genExtensionsFromPtree(ptree);
  } else {
    LOG(WARNING)
        << "System Extensions are not supported (requires macOS (>= 10.15))";
    return {};
  }
}
}
}
