/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/regex.hpp>

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

/// Location of the kernel panic crash logs in macOS
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";

// Apple's legacy panic log file format moved into a JSON string value
#ifdef __aarch64__
const std::string kPanicStringKey = "panicString"; // on ARM
#else
const std::string kPanicStringKey = "macOSPanicString"; // on x86
#endif

/// List of the days of the Week, used to grab our timestamp.
const std::set<std::string> kDays = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

/// Map of some of the values we parse out of the log file
const std::map<std::string, std::string> kKernelPanicKeys = {
    {"dependency", "dependencies"}, // no longer present in the file
    {"BSD process name corresponding to current thread",
     "name"}, // now just "Process name"
    {"System model name", "system_model"},
    {"System uptime in nanoseconds", "uptime"},
};

void readKernelPanic(const std::string& panicLogFilePath, QueryData& results) {
  Row r;
  r["registers"] = ""; // registers no longer reported since at least 10.14
  r["path"] = panicLogFilePath;
  std::string rawFileContent;
  std::vector<std::string> lines;

  if (!readFile(panicLogFilePath, rawFileContent).ok()) {
    VLOG(1) << "Could not read the panic log at " << panicLogFilePath;
    return;
  }

  // A "panic log" is now contained in JSON as a multi-lined "panic string",
  // in a file containing two JSON objects in series (non-standard JSON).
  // Find where the second JSON object begins. This is the "content":
  std::size_t contentJsonBegin = rawFileContent.find("}") + 1;

  try {
    pt::ptree panicLogHeader, panicLogContent;
    std::istringstream issHeader(rawFileContent.substr(0, contentJsonBegin));
    pt::read_json(issHeader, panicLogHeader);
    std::istringstream issContent(rawFileContent.substr(contentJsonBegin));
    pt::read_json(issContent, panicLogContent);

    // Neatly parse the fields represented in actual JSON:
#ifdef __aarch64__
    r["time"] = panicLogContent.get<std::string>("date", "");
    r["os_version"] = panicLogContent.get<std::string>("build", "");
    r["kernel_version"] = panicLogContent.get<std::string>("kernel", "");
    r["system_model"] = panicLogContent.get<std::string>("product", "");
#else
    r["time"] = panicLogHeader.get<std::string>("timestamp", "");
#endif

    std::string panicStringBlob =
        panicLogContent.get<std::string>(kPanicStringKey, "");

    lines = osquery::split(panicStringBlob, "\n"); // embedded newlines
  } catch (const pt::json_parser::json_parser_error& e) {
    VLOG(1) << "Could not parse JSON from " << panicLogFilePath << ": "
            << e.what();
    // In macOS 10.14 or earlier (not JSON-ified), just parse original content
    lines = osquery::split(rawFileContent, "\n");
  }

  // Crudely parse the fields from the lines in the panicString:
  for (auto it = lines.begin(); it != lines.end(); it++) {
    auto line = *it;
    boost::trim(line);

    // The panic log string is comprised of "KEY : VALUE" pairs but sometimes
    // VALUE contains the ":" character too. After this split, toks[0] holds a
    // kay of a key:value pair, toks[1] through toks[toks.size()-1] hold the
    // value.
    auto toks = osquery::split(line, ":");
    if (toks.size() == 0) {
      VLOG(1) << "Could not parse any key:value pair from the panic log line";
      continue;
    }

    // For macOS 10.14 and earlier, crudely parse the timestamp:
    auto timeTokens = osquery::split(toks[0], " ");
    if (timeTokens.size() >= 1 && kDays.count(timeTokens[0]) > 0) {
      r["time"] = line;
    }

    boost::regex rxSpaces("\\s+");
    if (boost::starts_with(toks[0], "Panicked task")) {
      r["name"] = boost::regex_replace(toks[toks.size() - 1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0],
                                  "last loaded kext at") && // older macOS
               toks.size() == 2) {
      r["last_loaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "last unloaded kext at") &&
               toks.size() == 2) {
      r["last_unloaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0],
                                  "last started kext at") && // newer macOS
               toks.size() == 2) {
      r["last_loaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "Backtrace") && // x86
               std::next(it) != lines.end()) {
      r["frame_backtrace"] = *(std::next(it));
    } else if (boost::starts_with(toks[0], "Panicked thread") && // ARM
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
    } else if (boost::starts_with(
                   toks[0], "Process name corresponding to current thread") &&
               std::next(it) != lines.end()) {
      r["name"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (kKernelPanicKeys.count(toks[0]) != 0 && toks.size() == 2) {
      // all of the other strings defined at the top of this file
      r[kKernelPanicKeys.at(toks[0])] = toks[1];
    } else {
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
} // namespace tables
} // namespace osquery
