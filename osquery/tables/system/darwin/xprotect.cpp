// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/sql.h>

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
      r["filetype"] = fileinfo.get<std::string>("LSDownloadContentTypeKey");
    } else {
      r["filetype"] = fileinfo.get("NSURLTypeIdentifierKey", "");
    }

    r["uses_pattern"] = (match.second.count("Pattern") > 0) ? "1" : "0";
    r["filename"] = fileinfo.get("NSURLNameKey", "");
    results.push_back(r);
  }
}

void genXProtectEntry(const pt::ptree &entry, QueryData& results) {
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

std::vector<std::string> getXProtectReportFiles(const std::string& home_dir) {
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

void genXProtectReport(const std::string& path, QueryData& results) {
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

  if (tree.count("root") == 0) {
    // Empty plist.
    return results;
  }

  for (const auto& it : tree.get_child("root")) {
    genXProtectEntry(it.second, results);
  }

  return results;
}
}
}
