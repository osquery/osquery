// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>

#include <glog/logging.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"
#include "osquery/status.h"

using osquery::Status;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::vector<std::string> kLaunchdSearchPaths = {
    "/System/Library/LaunchDaemons",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
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

std::vector<std::string> getLaunchdFiles() {
  std::vector<std::string> results;

  for (const auto& path : kLaunchdSearchPaths) {
    std::vector<std::string> files;
    auto s = osquery::listFilesInDirectory(path, files);
    if (s.ok()) {
      std::copy(files.begin(), files.end(), std::back_inserter(results));
    } else {
      VLOG(1) << "Error listing files in: " << path;
    }
  }

  std::vector<std::string> home_dirs;
  auto s = osquery::listFilesInDirectory("/Users", home_dirs);
  if (s.ok()) {
    for (const auto& home_dir : home_dirs) {
      std::string path = home_dir + "/Library/LaunchAgents";
      std::vector<std::string> files;
      auto user_list_s = osquery::listFilesInDirectory(path, files);
      if (user_list_s.ok()) {
        std::copy(files.begin(), files.end(), std::back_inserter(results));
      } else {
        VLOG(1) << "Error listing " << path << ": " << user_list_s.toString();
      }
    }
  } else {
    VLOG(1) << "Error listing /Users: " << s.toString();
  }

  return results;
}

Row parseLaunchdItem(const std::string& path, const pt::ptree& tree) {
  Row r;
  r["path"] = path;
  auto bits = osquery::split(path, "/");
  r["name"] = bits[bits.size() - 1];

  for (const auto& it : kLaunchdTopLevelStringKeys) {
    std::string item;
    try {
      item = tree.get<std::string>(it.first);
      if (it.first == "Program") {
        boost::replace_all(item, " ", "\\ ");
      }
    } catch (const pt::ptree_error& e) {
      VLOG(3) << "Error parsing " << it.first << " from " << path << ": "
              << e.what();
    }
    r[it.second] = item;
  }

  for (const auto& it : kLaunchdTopLevelArrayKeys) {
    try {
      pt::ptree subtree = tree.get_child(it.first);
      std::vector<std::string> array_results;
      for (const auto& each : subtree) {
        std::string item = each.second.get<std::string>("");
        boost::replace_all(item, " ", "\\ ");
        array_results.push_back(item);
      }
      r[it.second] = boost::algorithm::join(array_results, " ");
    } catch (pt::ptree_error& e) {
      VLOG(1) << "Error parsing " << it.first << " from " << path << ": "
              << e.what();
      r[it.second] = "";
    }
  }
  return r;
}

QueryData genLaunchd() {
  QueryData results;
  auto launchd_files = getLaunchdFiles();
  for (const auto& path : launchd_files) {
    pt::ptree tree;
    auto s = osquery::parsePlist(path, tree);
    if (s.ok()) {
      results.push_back(parseLaunchdItem(path, tree));
    } else {
      VLOG(1) << "Error parsing " << path << ": " << s.toString();
    }
  }
  return results;
}
}
}
