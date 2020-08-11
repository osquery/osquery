/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/plist.h>

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kManagedPoliciesCache = "/Library/Managed Preferences";

void genPolicy(const std::string& path,
               const std::string& username,
               QueryData& results) {
  Row r;
  r["username"] = fs::path(username).stem().string();
  r["domain"] = fs::path(path).stem().string();
  if (r.at("domain") == "complete") {
    // There is a special meta list that aggregates the user/system policy.
    return;
  }

  r["manual"] = "0";
  pt::ptree tree;
  if (!osquery::parsePlist(path, tree).ok()) {
    return;
  }

  // Iterate through the list of plist keys.
  std::map<std::string, std::string> settings;
  for (const auto& item : tree) {
    auto key = std::string(item.first.data());
    auto value = std::string(item.second.data());
    if (key == "_manualProfile") {
      r["manual"] = "1";
    } else if (key == "PayloadUUID") {
      r["uuid"] = std::move(value);
    } else {
      // If the key is not a meta uuid/managed then it is a policy name.
      settings[key] = value;
    }
  }

  // Iterate through the gathered policies names.
  for (const auto& setting : settings) {
    r["name"] = setting.first;
    r["value"] = setting.second;
    results.push_back(r);
  }
}

QueryData genManagedPolicies(QueryContext& context) {
  QueryData results;

  // All the managed preference policies in the root of the cache apply to
  // all users on this device.
  std::vector<std::string> policies;
  osquery::listFilesInDirectory(kManagedPoliciesCache, policies);
  for (const auto& policy : policies) {
    genPolicy(policy, "", results);
  }

  // Each folder should apply to a set of policies for a specific user.
  std::vector<std::string> usernames;
  osquery::listDirectoriesInDirectory(kManagedPoliciesCache, usernames);
  for (const auto& username : usernames) {
    policies.clear();
    osquery::listFilesInDirectory(username, policies);
    for (const auto& policy : policies) {
      genPolicy(policy, username, results);
    }
  }

  return results;
}
}
}
