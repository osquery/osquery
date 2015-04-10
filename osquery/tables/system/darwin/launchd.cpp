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
}
}
