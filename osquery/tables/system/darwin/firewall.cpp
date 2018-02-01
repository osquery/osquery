/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/darwin/firewall.h"

namespace pt = boost::property_tree;

#define DECLARE_TABLE_IMPLEMENTATION_alf
#include <generated/tables/tbl_alf_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_alf_exceptions
#include <generated/tables/tbl_alf_exceptions_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_alf_services
#include <generated/tables/tbl_alf_services_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_alf_explicit_auths
#include <generated/tables/tbl_alf_explicit_auths_defs.hpp>

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

  auto applications_tree = tree.get_child("applications");
  for (const auto& it : applications_tree) {
    Row r;

    if (it.second.get("alias", "").length() > 0) {
      std::string path;
      auto alias_data = it.second.get<std::string>("alias", "");

      if (pathFromPlistAliasData(alias_data, path).ok()) {
        r["path"] = path;
        r["state"] = INTEGER(it.second.get("state", -1));
        results.push_back(r);
      }
    }
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
