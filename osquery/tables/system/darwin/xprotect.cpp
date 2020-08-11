/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/darwin/plist.h>

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Path to XProtect.meta.plist and XProtect.plist
const std::string kXProtectPath =
    "/System/Library/CoreServices/"
    "CoreTypes.bundle/Contents/Resources/";

/// Relative path for each user's logging directory
const std::string kXProtectReportsPath = "/Library/Logs/DiagnosticReports";

void genMatches(const pt::ptree& entry, std::vector<Row>& results) {
  if (entry.count("Matches") == 0) {
    return;
  }

  bool optional = (entry.get("MatchType", "") == "MatchAny");
  for (const auto& match : entry.get_child("Matches")) {
    if (match.second.count("Matches") > 0) {
      genMatches(match.second, results);
      continue;
    }

    Row r;
    r["optional"] = (optional) ? "1" : "0";
    r["identity"] = match.second.get("Identity", "");
    if (match.second.count("MatchFile") == 0) {
      // There is no file in this match entry, odd.
      continue;
    }

    // This can contain any of Foundation/Classes/NSURL_Class keys.
    auto fileinfo = match.second.get_child("MatchFile");
    if (fileinfo.count("LSDownloadContentTypeKey") > 0) {
      r["filetype"] = fileinfo.get<std::string>("LSDownloadContentTypeKey", "");
    } else {
      r["filetype"] = fileinfo.get("NSURLTypeIdentifierKey", "");
    }

    r["uses_pattern"] = (match.second.count("Pattern") > 0) ? "1" : "0";
    r["filename"] = fileinfo.get("NSURLNameKey", "");
    results.push_back(r);
  }
}

inline void genXProtectEntry(const pt::ptree& entry, QueryData& results) {
  // Entry is an XProtect dictionary of meta data about the item.
  auto name = entry.get("Description", "");
  auto launch_type = entry.get("LaunchServices.LSItemContentType", "");

  // Get the list of matches
  std::vector<Row> file_matches;
  genMatches(entry, file_matches);

  for (auto& r : file_matches) {
    r["name"] = name;
    r["launch_type"] = launch_type;
    results.push_back(r);
  }
}

inline std::vector<std::string> getXProtectReportFiles(
    const std::string& home_dir) {
  std::vector<std::string> reports;
  std::vector<std::string> all_logs;

  // XProtect reports live in the user's diagnostic reports dir.
  auto reports_path = fs::path(home_dir) / kXProtectReportsPath;
  auto status = osquery::listFilesInDirectory(reports_path, all_logs);
  if (status.ok()) {
    for (const auto& log_file : all_logs) {
      // They are named with a "XProtect" prefix.
      if (log_file.find("XProtect") != std::string::npos) {
        reports.push_back(log_file);
      }
    }
  }

  return reports;
}

inline void genXProtectReport(const std::string& path, QueryData& results) {
  pt::ptree report;

  if (!osquery::parsePlist(path, report).ok()) {
    // Failed to read the XProtect plist format.
    return;
  }

  if (report.count("root") == 0) {
    // Unsupported/unknown report format.
    return;
  }

  for (const auto& entry : report.get_child("root")) {
    Row r;
    r["name"] = entry.second.get("XProtectSignatureName", "");
    if (r["name"].empty()) {
      continue;
    }

    r["user_action"] = entry.second.get("UserAction", "");
    r["time"] = entry.second.get("LSQuarantineTimeStamp", "");
    results.push_back(r);
  }
}

QueryData genXProtectReports(QueryContext& context) {
  QueryData results;

  // Loop over users for home directories
  auto users = SQL::selectAllFrom("users");
  for (const auto& user : users) {
    for (const auto& path : getXProtectReportFiles(user.at("directory"))) {
      genXProtectReport(path, results);
    }
  }

  return results;
}

QueryData genXProtectEntries(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  auto xprotect_path = fs::path(kXProtectPath) / "XProtect.plist";
  if (!osquery::pathExists(xprotect_path).ok()) {
    VLOG(1) << "XProtect.plist is missing";
    return results;
  }

  if (!osquery::parsePlist(xprotect_path, tree).ok()) {
    VLOG(1) << "Could not parse the XProtect.plist";
    return results;
  }

  if (tree.count("root") != 0) {
    for (const auto& it : tree.get_child("root")) {
      genXProtectEntry(it.second, results);
    }
  }

  return results;
}

QueryData genXProtectMeta(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  auto xprotect_meta = fs::path(kXProtectPath) / "XProtect.meta.plist";
  if (!osquery::pathExists(xprotect_meta).ok()) {
    VLOG(1) << "XProtect.meta.plist is missing";
    return results;
  }

  if (!osquery::parsePlist(xprotect_meta, tree).ok()) {
    VLOG(1) << "Could not parse the XProtect.meta.plist";
    return results;
  }

  for (const auto& it : tree) {
    if (it.first == "JavaWebComponentVersionMinimum") {
      Row r;
      r["identifier"] = "java";
      r["min_version"] = it.second.data();
      r["type"] = "plugin";
      results.push_back(std::move(r));
    } else if (it.first == "ExtensionBlacklist") {
      for (const auto& ext : it.second.get_child("Extensions")) {
        Row r;
        r["identifier"] = ext.second.get("CFBundleIdentifier", "");
        r["developer_id"] = ext.second.get("Developer Identifier", "");
        r["type"] = "extension";
        r["min_version"] = "any";
        results.push_back(std::move(r));
      }
    } else if (it.first == "PlugInBlacklist") {
      for (const auto& cat : it.second) {
        // Not sure why there's a category-like sub-dictionary, default="10".
        for (const auto& plug : cat.second) {
          Row r;
          r["identifier"] = plug.first;
          r["min_version"] = plug.second.get("MinimumPlugInBundleVersion", "");
          r["type"] = "plugin";
          r["developer_id"] = "";
          results.push_back(std::move(r));
        }
      }
    }
  }

  return results;
}
}
}
