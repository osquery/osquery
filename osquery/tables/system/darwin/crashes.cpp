/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace fs = boost::filesystem;
namespace alg = boost::algorithm;

namespace osquery {
namespace tables {

/// Locationg of the system application crash logs in OS X
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";
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
    // Note: We leave these two in, as they ensure we don't skip over the
    // register values in our check to ensure the token is a value we care
    // about.
    {"rax", "rax"},
    {"rdi", "rdi"},
};

void readCrashDump(const std::string& app_log, Row& r) {
  r["crash_path"] = app_log;
  std::string content;

  if (!readFile(app_log, content).ok()) {
    return;
  }

  // Variables for capturing the stack trace
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
      r["stack_trace"] = *(++it);
      crashed_thread_seen = false;
      continue;
    }

    if (kCrashDumpKeys.count(toks[0]) == 0) {
      continue;
    }

    // Process and grab all register values
    if (toks[0] == "rax") {
      r["registers"] = *it + *(++it);
    } else if (toks[0] == "Date/Time" && toks.size() >= 3) {
      // Reconstruct split date/time
      r[kCrashDumpKeys.at(toks[0])] = toks[1] + ":" + toks[2] + ":" + toks[3];
    } else if (toks[0] == "Crashed Thread") {
      // If the token is the Crashed thread, update the format string so
      // we can grab the stack trace later.
      auto t = split(toks[1], " ");
      if (t.size() == 0) {
        continue;
      }
      r[kCrashDumpKeys.at(toks[0])] = t[0];
      crashed_thread_format % r[kCrashDumpKeys.at(toks[0])];
      crashed_thread_seen = true;
    } else if (toks[0] == "Process" || toks[0] == "Parent Process") {
      // Use a regex to extract out the PID value
      const boost::regex e{"\\[\\d+\\]"};
      boost::smatch results;
      if (boost::regex_search(line, results, e)) {
        auto pid_str = std::string(results[0].first, results[0].second);
        auto pid = pid_str.substr(1, pid_str.size() - 2);
        r[kCrashDumpKeys.at(toks[0])] = pid;
      }
    } else if (toks[0] == "User ID") {
      r[kCrashDumpKeys.at(toks[0])] = toks[1];
    } else {
      // otherwise, process the line normally.
      r[kCrashDumpKeys.at(toks[0])] = toks[1];
    }
  }
}

QueryData genCrashLogs(QueryContext& context) {
  QueryData results;

  // Process system logs
  std::vector<std::string> files;
  if (listFilesInDirectory(kDiagnosticReportsPath, files).ok()) {
    for (const auto& slf : files) {
      // we only care about the .crash files.
      if (alg::ends_with(slf, ".crash")) {
        Row r;
        readCrashDump(slf, r);
        results.push_back(r);
      }
    }
  }

  // Process user logs
  auto users = usersFromContext(context);
  for (const auto& user : users) {
    std::vector<std::string> user_logs;
    auto dir = fs::path(user.at("directory")) / kDiagnosticReportsPath;
    if (listFilesInDirectory(dir, user_logs).ok()) {
      for (const auto& ulf : user_logs) {
        // we only care about the .crash files.
        if (alg::ends_with(ulf, ".crash")) {
          Row r;
          readCrashDump(ulf, r);
          results.push_back(r);
        }
      }
    }
  }
  return results;
}
}
}
