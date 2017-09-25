/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/darwin/firewall.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/**
 * @brief Well known path to the Application Layer Firewall configuration.
 *
 * This plist contains all of the details about the ALF.
 * It is used to populate all of the tables here.
 */
const std::string kALFPlistPath{"/Library/Preferences/com.apple.alf.plist"};

/// Well known keys within the plist containing settings.
const std::map<std::string, std::string> kTopLevelIntKeys{
    {"allowsignedenabled", "allow_signed_enabled"},
    {"allowdownloadsignedenabled", "allow_downloads_signed_enabled"},
    {"firewallunload", "firewall_unload"},
    {"globalstate", "global_state"},
    {"loggingenabled", "logging_enabled"},
    {"loggingoption", "logging_option"},
    {"stealthenabled", "stealth_enabled"},
};

/// Well known keys within the plist containing settings (as strings).
const std::map<std::string, std::string> kTopLevelStringKeys{
    {"version", "version"},
};

Status genALFTreeFromFilesystem(pt::ptree& tree) {
  Status s = osquery::parsePlist(kALFPlistPath, tree);
  if (!s.ok()) {
    TLOG << "Error parsing " << kALFPlistPath << ": " << s.toString();
  }
  return s;
}

QueryData parseALFTree(const pt::ptree& tree) {
  Row r;
  for (const auto& it : kTopLevelIntKeys) {
    int val = tree.get(it.first, -1);
    r[it.second] = INTEGER(val);
  }

  for (const auto& it : kTopLevelStringKeys) {
    std::string val = tree.get(it.second, "");
    r[it.first] = val;
  }

  return {r};
}

QueryData genALF(QueryContext& context) {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFTree(tree);
}

QueryData parseALFExceptionsTree(const pt::ptree& tree) {
  QueryData results;
  if (tree.count("exceptions") == 0) {
    return {};
  }

  auto exceptions_tree = tree.get_child("exceptions");
  for (const auto& it : exceptions_tree) {
    Row r;
    r["path"] = it.second.get("path", "");
    r["state"] = INTEGER(it.second.get("state", -1));
    results.push_back(r);
  }

  return results;
}

QueryData genALFExceptions(QueryContext& context) {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFExceptionsTree(tree);
}

QueryData parseALFExplicitAuthsTree(const pt::ptree& tree) {
  QueryData results;
  if (tree.count("explicitauths") == 0) {
    return {};
  }

  auto auths_tree = tree.get_child("explicitauths");
  for (const auto& it : auths_tree) {
    Row r;
    r["process"] = it.second.get("id", "");
    results.push_back(r);
  }

  return results;
}

QueryData genALFExplicitAuths(QueryContext& context) {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFExplicitAuthsTree(tree);
}

QueryData parseALFServicesTree(const pt::ptree& tree) {
  QueryData results;
  if (tree.count("firewall") == 0) {
    return {};
  }

  auto& firewall_tree = tree.get_child("firewall");
  for (const auto& it : firewall_tree) {
    Row r;
    r["service"] = it.first;
    r["process"] = it.second.get("proc", "");
    r["state"] = INTEGER(it.second.get("state", -1));
    results.push_back(r);
  }
  return results;
}

QueryData genALFServices(QueryContext& context) {
  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFServicesTree(tree);
}
}
}
