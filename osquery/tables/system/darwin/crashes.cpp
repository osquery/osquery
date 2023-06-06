/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>

#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/format.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;
namespace alg = boost::algorithm;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Set of x86 and x64 registers that we collect from crash logs
const std::set<std::string> kIntelRegisters = {
    "eax", "edi", "ss", "ds", "rax", "rdi", "r8", "r12", "rip", "x0", "x4"};

// TODO: ARM registers?
/// Set of ARM registers that we collect from crash logs
const std::set<std::string> kArmRegisters = {};

/// Location of the crash logs in macOS (also exists in each user's directory)
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";

/// Location of the user's mobile devices' crash logs in macOS
const std::string kMobileDiagnosticReportsPath =
    "/Library/Logs/CrashReporter/MobileDevice";

/// (macOS 11 and older) Map of the values we parse out of the '.crash' files
const std::map<std::string, std::string> kCrashDumpKeys = {
    {"Process", "pid"},
    {"Path", "path"},
    {"Log Location", "crash_path"}, // ignored (we know where it is)
    {"Identifier", "identifier"},
    {"Version", "version"},
    {"Parent Process", "parent"},
    {"Responsible", "responsible"},
    {"User ID", "uid"},
    {"Date/Time", "datetime"},
    {"Crashed Thread", "crashed_thread"},
    {"Exception Type", "exception_type"},
    {"Exception Codes", "exception_codes"},
    {"Exception Note", "exception_notes"},
    {"Triggered by Thread", "crashed_thread"},
};

void readCrashDumpJSON(const std::string& crashLogFilePath, Row& r) {
  r["crash_path"] = crashLogFilePath;
  std::string rawFileContent;

  if (!readFile(crashLogFilePath, rawFileContent).ok()) {
    VLOG(1) << "Could not read the crash log at " << crashLogFilePath;
    return;
  }

  // A "diagnostic report" (crash dump), as of macOS 12, is contained in a
  // file with the ".ips" extension containing two JSON objects in series
  // (non-standard JSON). Find where the second JSON object begins. This is
  // the "content":
  std::size_t contentJsonBegin = rawFileContent.find("}") + 1;

  try {
    pt::ptree crashLogHeader, crashLogContent;
    std::istringstream issHeader(rawFileContent.substr(0, contentJsonBegin));
    pt::read_json(issHeader, crashLogHeader);
    std::istringstream issContent(rawFileContent.substr(contentJsonBegin));
    pt::read_json(issContent, crashLogContent);

    // Parse the fields represented in the JSON:
    r["pid"] = crashLogContent.get<std::string>("pid", "");
    r["path"] = crashLogContent.get<std::string>("procPath", "");
    r["identifier"] = crashLogContent.get<std::string>("coalitionName", "");
    // TODO: if there is no version, do not report back " ()", instead leave
    // empty
    r["version"] =
        crashLogContent.get<std::string>(
            "bundleInfo.CFBundleShortVersionString", "") +
        " (" +
        crashLogContent.get<std::string>("bundleInfo.CFBundleVersion", "") +
        ")";
    r["parent"] = crashLogContent.get<std::string>("parentPid", "");
    r["responsible"] = crashLogContent.get<std::string>("procName", "");
    r["uid"] = crashLogContent.get<std::string>("userID", "");
    r["datetime"] = crashLogContent.get<std::string>("captureTime", "");
    r["crashed_thread"] =
        crashLogContent.get<std::string>("faultingThread", "");
    r["exception_type"] =
        crashLogContent.get<std::string>("exception.type", "") + " (" +
        crashLogContent.get<std::string>("exception.signal", "") + ")";
    r["exception_codes"] =
        crashLogContent.get<std::string>("exception.codes", "");
    r["exception_notes"] = ""; // as of macOS 12, this is no longer in the log
  } catch (const pt::json_parser::json_parser_error& e) {
    VLOG(1) << "Could not parse JSON from " << crashLogFilePath << ": "
            << e.what();
  }
}

void readCrashDump(const std::string& app_log, Row& r) {
  r["crash_path"] = app_log;
  std::string content;

  if (!readFile(app_log, content).ok()) {
    VLOG(1) << "Could not read the crash log at " << app_log;
    return;
  }

  // Variables for capturing the stack trace
  std::regex rx_spaces("\\s+");
  std::regex rx_spaces_colon(":\\s+");
  boost::format crashed_thread_format("Thread %1% Crashed");
  auto crashed_thread_seen = false;

  auto lines = split(content, "\n");
  for (auto it = lines.begin(); it != lines.end(); it++) {
    auto line = *it;
    // Tokenize first by colons
    auto toks = split(line, ":");

    if (toks.size() == 0) {
      continue;
    }

    // Grab the most recent stack trace line of the crashed thread.
    if (crashed_thread_seen && toks[0] == crashed_thread_format.str()) {
      auto nextLine = std::next(it);
      if (nextLine != lines.end()) {
        auto trace = std::string(*nextLine);
        auto cleanedTrace = std::regex_replace(trace, rx_spaces, " ");
        r["stack_trace"] = cleanedTrace;
      }
      crashed_thread_seen = false;
      continue;
    }

    if (kCrashDumpKeys.count(toks[0]) == 0 &&
        kIntelRegisters.count(toks[0]) == 0) {
      continue;
    }

    // Process and grab all register values
    if (kIntelRegisters.count(toks[0]) > 0) {
      boost::trim(line);

      line = std::regex_replace(line, rx_spaces, " ");
      line = std::regex_replace(line, rx_spaces_colon, ":");

      r["registers"] +=
          (r["registers"].empty()) ? std::move(line) : " " + std::move(line);

    } else if (toks[0] == "Date/Time") {
      // Reconstruct split date/time
      r[kCrashDumpKeys.at(toks[0])] =
          toks.size() == 4 ? toks[1] + ":" + toks[2] + ":" + toks[3] : "";
    } else if (toks[0] == "Crashed Thread" ||
               toks[0] == "Triggered by Thread") {
      // If the token is the Crashed thread, update the format string so
      // we can grab the stack trace later.
      auto t =
          toks.size() >= 2 ? split(toks[1], " ") : std::vector<std::string>();
      if (t.empty()) {
        continue;
      }
      auto formatCrashedThread = std::strtoul(t[0].c_str(), nullptr, 10);
      if (errno == EINVAL || errno == ERANGE) {
        continue;
      }
      r[kCrashDumpKeys.at(toks[0])] = INTEGER(formatCrashedThread);
      crashed_thread_format % r[kCrashDumpKeys.at(toks[0])];
      crashed_thread_seen = true;
    } else if (toks[0] == "Process" || toks[0] == "Parent Process") {
      // Use a regex to extract out the PID value
      const std::regex e{"\\[\\d+\\]"};
      std::smatch results;
      if (std::regex_search(line, results, e)) {
        auto pid_str = std::string(results[0].first, results[0].second);
        boost::erase_all(pid_str, "[");
        boost::erase_all(pid_str, "]");
        auto pid = std::strtoul(pid_str.c_str(), nullptr, 10);
        if (errno != EINVAL && errno != ERANGE) {
          r[kCrashDumpKeys.at(toks[0])] = INTEGER(pid);
        }
      }
    } else if (toks[0] == "User ID") {
      if (toks.size() == 2) {
        auto uid = std::strtoul(toks[1].c_str(), nullptr, 10);
        if (errno != EINVAL && errno != ERANGE) {
          r[kCrashDumpKeys.at(toks[0])] = INTEGER(uid);
        }
      }
    } else {
      // otherwise, process the line normally.
      r[kCrashDumpKeys.at(toks[0])] = toks.size() == 2 ? toks[1] : "";
    }
  }
}

QueryData genCrashLogs(QueryContext& context) {
  QueryData results;
  // TODO: pass the QueryData to the subroutines instead of the Row, have them
  // results.push_back(r) at the end?

  auto process_crash_logs = [&results](const fs::path& path,
                                       const std::string type) {
    std::vector<std::string> files;
    if (listFilesInDirectory(path, files)) {
      for (const auto& lf : files) {
        if (alg::ends_with(lf, ".crash") &&
            lf.find("LowBattery") == std::string::npos) {
          Row r;
          r["type"] = type;
          readCrashDump(lf, r);
          results.push_back(r);
        } else if (alg::ends_with(lf, ".ips")) {
          Row r;
          r["type"] = type;
          readCrashDumpJSON(lf, r);
          results.push_back(r);
        }
      }
    }
  };

  // Process system logs
  if (context.constraints["uid"].notExistsOrMatches("0")) {
    process_crash_logs(kDiagnosticReportsPath, "application");
  }

  // As of macOS 12, also check the subdirectory, /Retired
  auto systemRetiredPath = fs::path(kDiagnosticReportsPath) / "Retired";
  process_crash_logs(systemRetiredPath, "application");

  // Process user logs
  auto users = usersFromContext(context);
  for (const auto& user : users) {
    auto user_home = fs::path(user.at("directory")) / kDiagnosticReportsPath;
    process_crash_logs(user_home, "application");

    // As of macOS 12, also check the subdirectory, /Retired
    auto userRetiredPath = user_home / "Retired";
    process_crash_logs(userRetiredPath, "application");

    // Process mobile crash logs
    auto user_mobile_root =
        fs::path(user.at("directory")) / kMobileDiagnosticReportsPath;
    std::vector<std::string> mobile_paths;
    if (listDirectoriesInDirectory(user_mobile_root, mobile_paths)) {
      for (const auto& mobile_device : mobile_paths) {
        process_crash_logs(mobile_device, "mobile");
      }
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
