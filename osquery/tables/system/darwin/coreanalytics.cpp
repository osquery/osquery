/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>
#include <sstream>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include "osquery/core/conversions.h"

#include <boost/property_tree/json_parser.hpp>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {


const std::string kCoreAnalyticsPath =
    "/Library/Logs/DiagnosticReports/%.core_analytics";

const std::map<std::string, std::string> kCoreAnalyticsStringKeys = {
    {"activations", "activations"},
    {"activeTime", "active_time"},
    {"activityPeriods", "activity_periods"},
    {"appDescription", "app_description"},
    {"foreground", "foreground"},
    {"idleTimeouts", "idle_timeouts"},
    {"launches", "launches"},
    {"powerTime", "power_time"},
    {"processName", "process_name"},
    {"uptime", "uptime"},
};

const std::map<std::string, std::string> kCoreAnalyticsTopLevelKeys = {
    {"name", "subsystem_name"},
    {"uuid", "subsystem_uuid"},
    {"message", "message"},
};

void genCoreAnalyticsRecord(const pt::ptree& tree,
                            const fs::path& path,
                            const std::string diag_start,
                            const std::string diag_end,
                            QueryData& results) {
  Row r;
  r["source_file"] = path.string();
  r["diag_start"] = diag_start;
  r["diag_end"] = diag_end;

  boost::optional<const pt::ptree&> child;
  pt::ptree msg_tree;
  for (const auto& it : kCoreAnalyticsTopLevelKeys) {
    // For known string-values, the column is the value.
    if (it.first == "message") {
      child = tree.get_child_optional("message");
      if (child) {
        msg_tree = tree.get_child("message");
        for (const auto& sKeys : kCoreAnalyticsStringKeys) {
          if(sKeys.first == "appDescription"){
              std::vector<std::string> parsedDescription = osquery::split(msg_tree.get("appDescription",""),"|||");
              r["app_name"] = parsedDescription[0];
              r["app_version"] = parsedDescription[1];
          }
          r[sKeys.second] = msg_tree.get(sKeys.first, "");
        }
      }
    } else {
      r[it.second] = tree.get(it.first, "");
    }
  }

  results.push_back(std::move(r));
}

QueryData genCoreAnalyticsResults(QueryContext& context) {
  QueryData results;
  std::vector<std::string> diagFiles;
  osquery::resolveFilePattern(kCoreAnalyticsPath, diagFiles);
  pt::ptree tree;

  for (const auto& path : diagFiles) {
    if (!osquery::pathExists(path)) {
      continue;
    }
    std::string content;
    osquery::readFile(path, content);
    std::stringstream contentStream(content);

    std::string diag_start;
    std::string diag_end;
    pt::ptree marker_tree;

    for (auto& line : osquery::split(content, "\n")) {
      boost::trim(line);
      if (!osquery::parseJSONContent(line, tree).ok()) {
        std::cout << "Error parsing JSON: " << path;
        continue;
      }
     
    // timestamp is the diagnostic end time, located in the first record in the file
      boost::optional<const pt::ptree&> child;
      child = tree.get_child_optional("timestamp");
      if (child) {
        diag_end = tree.get("timestamp","");
      }

      child = tree.get_child_optional("startTimestamp");
      if (child) {
        diag_start = tree.get("startTimestamp","");
      }

      // Only look at records from comappleosanalyticsappUsage 
      if(tree.get("name","") == "comappleosanalyticsappUsage"){
      genCoreAnalyticsRecord(tree, path, diag_start, diag_end, results);
    }
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
