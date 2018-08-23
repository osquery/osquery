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

#include "osquery/core/conversions.h"
#include <osquery/core.h>
#include <osquery/core/json.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace rj = rapidjson;

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

const std::map<std::string, std::string> parseMessage(const rj::Value& obj) {
  std::map<std::string, std::string> results;

  for (const auto& i : obj.GetObject()) {
    auto it = kCoreAnalyticsStringKeys.find(i.name.GetString());
    if (it != kCoreAnalyticsStringKeys.end()) {
      if (strcmp(i.name.GetString(), "appDescription") == 0 &&
          i.value.IsString()) {
        std::vector<std::string> parsedDescription =
            osquery::split(i.value.GetString(), "|||");
        results["app_name"] = parsedDescription[0];
        results["app_version"] = parsedDescription[1];
      }

      if (i.value.IsString()) {
        results[it->second] = i.value.GetString();
      } else {
        results[it->second] = std::to_string(i.value.GetInt());
      }
    }
  }
  return results;
}

void genCoreAnalyticsRecord(const JSON& doc,
                            const fs::path& path,
                            const std::string diag_start,
                            const std::string diag_end,
                            QueryData& results) {
  Row r;
  r["source_file"] = path.string();
  r["diag_start"] = diag_start;
  r["diag_end"] = diag_end;

  for (const auto& td : doc.doc().GetObject()) {
    auto itr = kCoreAnalyticsTopLevelKeys.find(td.name.GetString());
    if (itr != kCoreAnalyticsTopLevelKeys.end()) {
      if (strcmp(td.name.GetString(), "message") == 0 && td.value.IsObject()) {
        // parsing the message block is messy, moved to its own function
        auto msg_results = parseMessage(td.value);
        for (const auto& m : msg_results) {
          r[m.first] = m.second;
        }
      } else {
        r[itr->second] = td.value.GetString();
      }
    }
  }

  results.push_back(std::move(r));
}

QueryData genCoreAnalyticsResults(QueryContext& context) {
  QueryData results;
  std::vector<std::string> diagFiles;
  osquery::resolveFilePattern(kCoreAnalyticsPath, diagFiles);

  for (const auto& path : diagFiles) {
    if (!osquery::pathExists(path)) {
      continue;
    }
    std::string content;
    osquery::readFile(path, content);
    std::stringstream contentStream(content);

    std::string diag_start;
    std::string diag_end;

    for (auto& line : osquery::split(content, "\n")) {
      boost::trim(line);
      auto obj = JSON::newObject();

      Status s = obj.fromString(line);
      if (!s.ok()) {
        std::cout << "Error parsing JSON: " << path;
        continue;
      }

      auto itr = obj.doc().FindMember("timestamp");
      if (itr != obj.doc().MemberEnd()) {
        // format 2018-07-17 04:06:59.79 -0400
        struct tm tm;
        // if strptime fails set diag_end to whatever was read from the file
        auto ts = std::string(itr->value.GetString());
        auto dt = ts.substr(0, 19) + ts.substr(22, 6);
        if (strptime(dt.c_str(), "%F %T %z", &tm) == nullptr) {
          diag_end = itr->value.GetString();
        } else {
          diag_end = std::to_string(toUnixTime(&tm));
        }
      }

      itr = obj.doc().FindMember("startTimestamp");
      if (itr != obj.doc().MemberEnd()) {
        // format 2018-07-16T11:29:04Z
        struct tm tm1;
        // if strptime fails set diag_end to whatever was read from the file
        if (strptime(itr->value.GetString(), "%FT%TZ", &tm1) == nullptr) {
          diag_start = itr->value.GetString();
        } else {
          diag_start = std::to_string(toUnixTime(&tm1));
        }
      }
      // Only look at records from comappleosanalyticsappUsage
      itr = obj.doc().FindMember("name");
      if (itr != obj.doc().MemberEnd()) {
        if (strcmp(itr->value.GetString(), "comappleosanalyticsappUsage") ==
            0) {
          genCoreAnalyticsRecord(obj, path, diag_start, diag_end, results);
        }
      }
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery
