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

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>

namespace fs = boost::filesystem;
namespace alg = boost::algorithm;

namespace osquery {
namespace tables {

/// Set of registers, x86 and x64, that we collect from crash logs
const std::set<std::string> kRegisters = {
    "eax", "edi", "ss", "ds", "rax", "rdi", "r8", "r12", "rip", "x0", "x4"};

/// Location of the system application crash logs in OS X
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";

/// Location of the user mobile devices crash logs in OS X
const std::string kMobileDiagnosticReportsPath =
    "/Library/Logs/CrashReporter/MobileDevice";

/// Map of the values we currently parse out of the log file
const std::map<std::string, std::string> kCrashDumpKeys = {
    {"Process", "pid"},
    {"Path", "path"},
    {"Log Location", "crash_path"},
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

void readCrashDump(const std::string& app_log, Row& r) {
  r["crash_path"] = app_log;
  std::string content;

  if (!readFile(app_log, content).ok()) {
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

    if (kCrashDumpKeys.count(toks[0]) == 0 && kRegisters.count(toks[0]) == 0) {
      continue;
    }

    // Process and grab all register values
    if (kRegisters.count(toks[0]) > 0) {
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
        }
      }
    }
  };

  // Process system logs
  if (context.constraints["uid"].notExistsOrMatches("0")) {
    process_crash_logs(kDiagnosticReportsPath, "application");
  }

  // Process user logs
  auto users = usersFromContext(context);
  for (const auto& user : users) {
    auto user_home = fs::path(user.at("directory")) / kDiagnosticReportsPath;
    process_crash_logs(user_home, "application");

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
}
}
