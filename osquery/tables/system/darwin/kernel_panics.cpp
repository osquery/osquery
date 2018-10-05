/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/regex.hpp>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace fs = boost::filesystem;
namespace alg = boost::algorithm;

namespace osquery {
namespace tables {

/// Location of the kernel panic crash logs in OS X
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";

/// List of all register values we wish to catch
const std::set<std::string> kKernelRegisters = {
    "CR0",
    "RAX",
    "RSP",
    "R8",
    "R12",
    "RFL",
};

/// List of the days of the Week, used to grab our timestamp.
const std::set<std::string> kDays = {"Mon", "Tue", "Wed", "Thu", "Fri"};

/// Map of the values we currently parse out of the log file
const std::map<std::string, std::string> kKernelPanicKeys = {
    {"dependency", "dependencies"},
    {"BSD process name corresponding to current thread", "name"},
    {"System model name", "system_model"},
    {"System uptime in nanoseconds", "uptime"},
};

void readKernelPanic(const std::string& appLog, QueryData& results) {
  Row r;
  r["path"] = appLog;
  std::string content;

  if (!readFile(appLog, content).ok()) {
    return;
  }

  boost::regex rxSpaces("\\s+");
  auto lines = osquery::split(content, "\n");
  for (auto it = lines.begin(); it != lines.end(); it++) {
    auto line = *it;
    boost::trim(line);

    auto toks = osquery::split(line, ":");
    if (toks.size() == 0) {
      continue;
    }

    auto timeTokens = osquery::split(toks[0], " ");
    if (timeTokens.size() >= 1 && kDays.count(timeTokens[0]) > 0) {
      r["time"] = line;
    }

    if (kKernelRegisters.count(toks[0]) > 0) {
      auto registerTokens = osquery::split(line, ",");
      if (registerTokens.size() == 0) {
        continue;
      }

      for (auto& tok_ : registerTokens) {
        auto regHolder = osquery::split(tok_, ":");
        if (regHolder.size() != 2) {
          continue;
        }
        auto reg = std::move(regHolder[0]);
        auto val = std::move(regHolder[1]);
        if (reg.size() > 0 && val.size() > 0) {
          std::string regLine = reg + ":" + val;
          r["registers"] += (r["registers"].empty()) ? std::move(regLine)
                                                     : " " + std::move(regLine);
        }
      }
    } else if (boost::starts_with(toks[0], "last loaded kext at") &&
               toks.size() == 2) {
      r["last_loaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "last unloaded kext at") &&
               toks.size() == 2) {
      r["last_unloaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "Backtrace") &&
               std::next(it) != lines.end()) {
      r["frame_backtrace"] = *(std::next(it));
    } else if (boost::starts_with(toks[0], "Kernel Extensions in backtrace") &&
               std::next(it) != lines.end()) {
      r["module_backtrace"] = *(std::next(it));
    } else if (boost::starts_with(toks[0], "Mac OS version") &&
               std::next(it) != lines.end()) {
      r["os_version"] = *(std::next(it));
    } else if (boost::starts_with(toks[0], "Kernel version") &&
               std::next(it) != lines.end()) {
      r["kernel_version"] = *(std::next(it));
    } else if (kKernelPanicKeys.count(toks[0]) != 0 && toks.size() == 2) {
      r[kKernelPanicKeys.at(toks[0])] = toks[1];
    }
  }
  results.push_back(r);
}

QueryData genKernelPanics(QueryContext& context) {
  QueryData results;

  if (context.constraints["uid"].notExistsOrMatches("0")) {
    std::vector<std::string> files;
    if (listFilesInDirectory(kDiagnosticReportsPath, files)) {
      for (const auto& lf : files) {
        if (alg::ends_with(lf, ".panic")) {
          readKernelPanic(lf, results);
        }
      }
    }
  }

  return results;
}
}
}
