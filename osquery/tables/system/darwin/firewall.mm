/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/darwin/firewall.h>
#include <osquery/utils/darwin/plist.h>
#include <osquery/utils/darwin/system_profiler.h>

#import <CoreFoundation/CoreFoundation.h>

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
  const auto& qd = SQL::selectAllFrom("os_version");
  if (qd.size() != 1) {
    LOG(ERROR) << "Couldn't determine macOS version";
    return {};
  }

  if (qd.front().at("major") < "15") {
    pt::ptree tree;
    auto s = genALFTreeFromFilesystem(tree);
    if (!s.ok()) {
      return {};
    }
    return parseALFTree(tree);
  } else {
    // Starting on version 15 ALF information is no longer on a plist file, see
    // https://developer.apple.com/documentation/macos-release-notes/macos-15-release-notes#Deprecations
    return genALFFromSystemProfiler();
  }
}

QueryData genALFFromSystemProfiler() {
  QueryData results;
  @autoreleasepool {
    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPFirewallDataType", result);
    if (!status.ok()) {
      LOG(ERROR) << "failed to get SPFirewallDataType config: "
                 << status.getMessage();
      return {};
    }

    Row r;

    // _versionInfo
    NSDictionary* version_info = [result objectForKey:@"_versionInfo"];
    if ([version_info
            valueForKey:@"com.apple.SystemProfiler.SPFirewallReporter"]) {
      const std::string version = [[version_info
          valueForKey:@"com.apple.SystemProfiler.SPFirewallReporter"]
          UTF8String];
      r["version"] = version;
    }

    NSDictionary* report = [[result objectForKey:@"_items"] lastObject];

    // spfirewall_globalstate
    if ([report valueForKey:@"spfirewall_globalstate"]) {
      const std::string s =
          [[report valueForKey:@"spfirewall_globalstate"] UTF8String];
      if (s == "spfirewall_globalstate_limit_connections") {
        r["global_state"] = INTEGER(1);
      } else if (s == "spfirewall_globalstate_block_all") {
        r["global_state"] = INTEGER(2);
      } else if (s == "spfirewall_globalstate_allow_all") {
        r["global_state"] = INTEGER(0);
      } else {
        LOG(ERROR) << "unknown value for spfirewall_globalstate: \"" << s
                   << "\"";
      }
    }

    // spfirewall_stealthenabled
    if ([report valueForKey:@"spfirewall_stealthenabled"]) {
      const std::string s =
          [[report valueForKey:@"spfirewall_stealthenabled"] UTF8String];
      if (s == "Yes") {
        r["stealth_enabled"] = INTEGER(1);
      } else if (s == "No") {
        r["stealth_enabled"] = INTEGER(0);
      } else {
        LOG(ERROR) << "unknown value for spfirewall_stealthenabled: \"" << s
                   << "\"";
      }
    }

    // spfirewall_loggingenabled
    if ([report valueForKey:@"spfirewall_loggingenabled"]) {
      const std::string s =
          [[report valueForKey:@"spfirewall_loggingenabled"] UTF8String];
      if (s == "Yes") {
        r["logging_enabled"] = INTEGER(1);
      } else if (s == "No") {
        r["logging_enabled"] = INTEGER(0);
      } else {
        LOG(ERROR) << "unknown value for spfirewall_loggingenabled: \"" << s
                   << "\"";
      }
    }

    results.push_back(r);
  }
  return results;
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
      auto status = pathFromNestedPlistAliasData(alias_data, path);

      if (!status.ok()) {
        TLOG << "Could not parse nested plist for applications: "
             << status.getMessage();
        continue;
      }

      r["path"] = path;
      r["state"] = INTEGER(it.second.get("state", -1));
      results.push_back(r);
    }
  }

  return results;
}

QueryData genALFExceptions(QueryContext& context) {
  const auto& qd = SQL::selectAllFrom("os_version");
  if (qd.size() != 1) {
    LOG(ERROR) << "Couldn't determine macOS version";
    return {};
  }

  if (qd.front().at("major") < "15") {
    pt::ptree tree;
    auto s = genALFTreeFromFilesystem(tree);
    if (!s.ok()) {
      return {};
    }
    return parseALFExceptionsTree(tree);
  } else {
    // Starting on version 15 ALF information is no longer on a plist file, see
    // https://developer.apple.com/documentation/macos-release-notes/macos-15-release-notes#Deprecations
    return genALFExceptionsFromSystemProfiler();
  }
}

QueryData genALFExceptionsFromSystemProfiler() {
  QueryData results;
  @autoreleasepool {
    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPFirewallDataType", result);
    if (!status.ok()) {
      LOG(ERROR) << "failed to get SPFirewallDataType config: " +
                        status.getMessage();
      return {};
    }

    NSDictionary* report = [[result objectForKey:@"_items"] lastObject];

    // spfirewall_applications
    if ([report valueForKey:@"spfirewall_applications"]) {
      NSDictionary* apps = [report valueForKey:@"spfirewall_applications"];

      for (NSString* key in apps) {
        NSString* value = apps[key];
        Row r;
        const std::string skey = [key UTF8String];
        r["path"] = skey;
        const std::string svalue = [value UTF8String];
        if (svalue == "spfirewall_allow_all") {
          r["state"] = INTEGER(
              0); // to match the state=0 on macOS versions lower than 15
        } else if (svalue == "spfirewall_block_all") {
          r["state"] = INTEGER(
              2); // to match the state=2 on macOS versions lower than 15
        } else {
          LOG(ERROR) << "unknown value for spfirewall_applications \"" << skey
                     << "\": \"" << svalue << "\"";
          continue;
        }
        results.push_back(r);
      };
    }
  }
  return results;
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
  const auto& qd = SQL::selectAllFrom("os_version");
  if (qd.size() != 1) {
    LOG(ERROR) << "Couldn't determine macOS version";
    return {};
  }

  if (qd.front().at("major") >= "15") {
    // Currently not supported on macOS 15+.
    VLOG(1) << "alf_explicit_auths is currently not supported on macOS 15";
    return {};
  }

  pt::ptree tree;
  auto s = genALFTreeFromFilesystem(tree);
  if (!s.ok()) {
    return {};
  }
  return parseALFExplicitAuthsTree(tree);
}
} // namespace tables
} // namespace osquery
