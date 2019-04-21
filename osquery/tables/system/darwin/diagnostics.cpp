/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/string/replace.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/conversions/split.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

// read data from core_analytics file
void genDiagnosticsFromFile(const boost::filesystem::path& diagnostics_file,
                            QueryData& results) {
  std::string diagnostics_content;

  if (forensicReadFile(diagnostics_file, diagnostics_content).ok()) {
    std::string diag_start;
    std::string diag_end;

    for (const auto& line : split(diagnostics_content, "\n")) {
      if (line.find("startTimestamp") != std::string::npos) {
        pt::ptree tree;
        std::stringstream ss(line);

        pt::read_json(ss, tree);
        diag_start = tree.get<std::string>("startTimestamp");

        // remove letters in timestamp
        boost::replace_all(diag_start, "T", " ");
        boost::replace_all(diag_start, "Z", "");
      }

      if (line.find("timestamp") != std::string::npos &&
          line.find("os_version") != std::string::npos) {
        pt::ptree tree;
        std::stringstream ss(line);
        pt::read_json(ss, tree);
        diag_end = tree.get<std::string>("timestamp");

        // split timestamp string by millisecond
        diag_end = diag_end.substr(0, diag_end.find("."));

        std::tm t = {};
        std::stringstream ss_diag(diag_end);
        ss_diag >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");

        // check if daylight savings time is in effect
        t.tm_isdst = -1;

        time_t diag_end_epoch = std::mktime(&t);

        std::stringstream diag_end_ss;
        diag_end_ss << std::put_time(std::gmtime(&diag_end_epoch),
                                     "%Y-%m-%d %H:%M:%S");
        diag_end = diag_end_ss.str();
      }

      try {
        if (line.find("appDescription") != std::string::npos) {
          pt::ptree tree;
          std::stringstream ss(line);
          pt::read_json(ss, tree);

          Row r;

          r["diagnostic_start"] = diag_start;
          r["diagnostic_end"] = diag_end;
          r["path"] = diagnostics_file.string();
          r["name"] = tree.get<std::string>("name");
          r["uuid"] = tree.get<std::string>("uuid");
          r["process_name"] = tree.get<std::string>("message.processName");
          r["app_description"] =
              tree.get<std::string>("message.appDescription");
          r["foreground"] = tree.get<std::string>("message.foreground");
          r["uptime"] = INTEGER(tree.get<int>("message.uptime"));
          r["power_time"] = INTEGER(tree.get<int>("message.powerTime"));
          r["active_time"] = INTEGER(tree.get<int>("message.activeTime"));
          r["activations"] = INTEGER(tree.get<int>("message.activations"));
          r["launches"] = INTEGER(tree.get<int>("message.launches"));
          r["activity_periods"] =
              INTEGER(tree.get<int>("message.activityPeriods"));
          results.push_back(r);
        }
      } catch (const std::exception& e) {
        VLOG(1) << "Error reading .core_analytics json: " << e.what();
      }
    }
  }
}

void genDiagnosticData(QueryData& results) {
  boost::filesystem::path diagnostics = "/Library/Logs/DiagnosticReports/";
  diagnostics /= "*.core_analytics";
  std::vector<std::string> diagnostic_files;
  resolveFilePattern(diagnostics, diagnostic_files);

  // loop through all core_analytics files in directory
  for (const auto& hfile : diagnostic_files) {
    boost::filesystem::path diagnostic_file = hfile;

    std::string diagnostics_content;
    if (forensicReadFile(diagnostic_file, diagnostics_content).ok()) {
    }
    genDiagnosticsFromFile(diagnostic_file, results);
  }
}

QueryData genDiagnostics(QueryContext& context) {
  QueryData results;

  genDiagnosticData(results);

  return results;
}
} // namespace tables
} // namespace osquery
