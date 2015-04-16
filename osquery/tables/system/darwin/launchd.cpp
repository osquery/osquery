/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLaunchdSearchPaths = {
    "/System/Library/LaunchDaemons",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/Library/LaunchAgents",
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

void genLaunchdItem(const std::string& path, QueryData& results) {
  pt::ptree tree;
  if (!osquery::parsePlist(path, tree).ok()) {
    TLOG << "Could not parse launchd plist: " << path;
    return;
  }

  Row r;
  r["path"] = path;
  r["name"] = fs::path(path).filename().string();
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

  results.push_back(r);
}

QueryData genLaunchd(QueryContext& context) {
  QueryData results;

  for (const auto& search_path : kLaunchdSearchPaths) {
    std::vector<std::string> launchers;
    osquery::listFilesInDirectory(search_path, launchers);
    for (const auto& launcher : launchers) {
      if (!context.constraints["path"].matches(launcher)) {
        // Optimize by not searching when a path is a constraint.
        continue;
      }
      genLaunchdItem(launcher, results);
    }
  }

  auto homes = osquery::getHomeDirectories();
  for (const auto& home : homes) {
    for (const auto& search_path : kUserLaunchdSearchPaths) {
      std::vector<std::string> launchers;
      osquery::listFilesInDirectory(home / search_path, launchers);
      for (const auto& launcher : launchers) {
        if (!context.constraints["path"].matches(launcher)) {
          continue;
        }
        genLaunchdItem(launcher, results);
      }
    }
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
