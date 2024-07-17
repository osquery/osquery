/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLaunchdSearchPaths = {
    "/System/Library/LaunchDaemons",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/Apple/System/Library/LaunchDaemons",
    "/Library/Apple/System/Library/LaunchAgents",
};

const std::vector<std::string> kUserLaunchdSearchPaths = {
    "/Library/LaunchAgents",
};

const std::map<std::string, std::string> kLaunchdTopLevelStringKeys = {
    {"Label", "label"},
    {"RunAtLoad", "run_at_load"},
    {"KeepAlive", "keep_alive"},
    {"StandardOutPath", "stdout_path"},
    {"StandardErrorPath", "stderr_path"},
    {"inetdCompatibility", "inetd_compatibility"},
    {"StartInterval", "start_interval"},
    {"Program", "program"},
    {"StartOnMount", "start_on_mount"},
    {"OnDemand", "on_demand"},
    {"Disabled", "disabled"},
    {"UserName", "username"},
    {"GroupName", "groupname"},
    {"RootDirectory", "root_directory"},
    {"WorkingDirectory", "working_directory"},
    {"ProcessType", "process_type"},
};

const std::map<std::string, std::string> kLaunchdTopLevelArrayKeys = {
    {"ProgramArguments", "program_arguments"},
    {"WatchPaths", "watch_paths"},
    {"QueueDirectories", "queue_directories"},
};

const std::string kLaunchdOverridesPath =
    "/var/db/launchd.db/%/overrides.plist";

void genLaunchdItem(const pt::ptree& tree,
                    const fs::path& path,
                    QueryData& results) {
  Row r;
  r["path"] = path.string();
  r["name"] = path.filename().string();
  for (const auto& it : kLaunchdTopLevelStringKeys) {
    // For known string-values, the column is the value.
    r[it.second] = tree.get(it.first, "");
  }

  for (const auto& it : kLaunchdTopLevelArrayKeys) {
    // Otherwise walk an array item and join the arguments.
    if (tree.count(it.first) == 0) {
      continue;
    }

    auto subtree = tree.get_child(it.first);
    std::vector<std::string> arguments;
    for (const auto& argument : subtree) {
      arguments.push_back(argument.second.get<std::string>(""));
    }
    r[it.second] = boost::algorithm::join(arguments, " ");
  }

  results.push_back(std::move(r));
}

QueryData genLaunchd(QueryContext& context) {
  QueryData results;

  std::vector<std::string> launchers;
  for (const auto& search_path : kLaunchdSearchPaths) {
    osquery::listFilesInDirectory(search_path, launchers);
  }

  // List all users on the system, and walk common search paths with homes.
  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    for (const auto& path : kUserLaunchdSearchPaths) {
      osquery::listFilesInDirectory(home / path, launchers);
    }
  }

  // The osquery::parsePlist method will reset/clear a property tree.
  // Keeping the data structure in a larger scope preserves allocations
  // between similar-sized trees.
  pt::ptree tree;

  // For each found launcher (plist in known paths) parse the plist.
  for (const auto& path : launchers) {
    if (!context.constraints["path"].matches(path)) {
      // Optimize by not searching when a path is a constraint.
      continue;
    }

    if (!osquery::pathExists(path)) {
      continue;
    }

    if (!osquery::parsePlist(path, tree).ok()) {
      TLOG << "Error parsing launch daemon/agent plist: " << path;
      continue;
    }

    // Using the parsed plist, pull out each set of interesting keys.
    genLaunchdItem(tree, path, results);
  }

  return results;
}

void genLaunchdOverride(const fs::path& path, QueryData& results) {
  Row r;
  r["path"] = path.string();
  // The overrides may be restricted to a user, based on the folder.
  auto group = osquery::split(path.parent_path().filename().string(), ".");
  r["uid"] = (group.size() == 5) ? BIGINT(group.at(4)) : "0";

  pt::ptree tree;
  if (!osquery::parsePlist(path, tree).ok()) {
    return;
  }

  // Include a row for each label : key since we do not know the set of keys
  // that may be overridden.
  for (const auto& daemon : tree) {
    r["label"] = daemon.first.data();
    for (const auto& item : daemon.second) {
      r["key"] = item.first.data();
      r["value"] = item.second.get_value("");
      results.push_back(r);
    }
  }
}

QueryData genLaunchdOverrides(QueryContext& context) {
  QueryData results;

  std::vector<std::string> overrides;
  osquery::resolveFilePattern(kLaunchdOverridesPath, overrides);
  for (const auto& group : overrides) {
    genLaunchdOverride(group, results);
  }

  return results;
}
}
}
