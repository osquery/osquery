/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/regex.hpp>
#include <boost/property_tree/json_parser.hpp>

//we might not be linking with these Boost components:
//#include <boost/iostreams/device/array.hpp>
//#include <boost/iostreams/stream.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/logger/logger.h>

namespace fs = boost::filesystem;
namespace alg = boost::algorithm;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/// Location of the kernel panic crash logs in macOS
const std::string kDiagnosticReportsPath = "/Library/Logs/DiagnosticReports";

// macOS 11 moved the old panic log file from 10.15 into a JSON string value
const std::string kPanicStringKey = "macOSPanicString";  // as of macOS 12
// const std::string kPanicStringkey = "panicString"; // in macOS 11, apparently

/// List of all x86-64 register values we wish to catch
const std::set<std::string> kX86KernelRegisters = {
    "CR0",
    "RAX",
    "RSP",
    "R8",
    "R12",
    "RFL",
};

/// List of the days of the Week, used to grab our timestamp.
const std::set<std::string> kDays = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

/// Map of some of the values we parse out of the log file
const std::map<std::string, std::string> kKernelPanicKeys = {
    {"dependency", "dependencies"},  // macOS 12: no longer present in the file
    {"BSD process name corresponding to current thread", "name"},  // <= 10.15
    {"System model name", "system_model"},
    {"System uptime in nanoseconds", "uptime"},
};

void readKernelPanic(const std::string& panicLogFilePath, QueryData& results) {
  Row r;
  r["path"] = panicLogFilePath;
  std::string rawFileContent;

  if (!readFile(panicLogFilePath, rawFileContent).ok()) {
    VLOG(1) << "Could not read the panic log at " << panicLogFilePath;
    return;
  }

  auto lines = osquery::split(rawFileContent, "\n");  // actual newlines
  
  // if (macOS major version >= 11) {
    // Legacy format panic log content is now in a JSON-style container.
    // Perform some additional unwrapping:
    try {
      pt::ptree panicLogHeader, panicLogContent;
      std::istringstream issHeader( lines[0] );
      pt::read_json(issHeader, panicLogHeader);
      r["time"] = panicLogHeader.get<std::string>("timestamp", "");
        
      std::istringstream issContent( lines[1] );
      pt::read_json(issContent, panicLogContent);
        
      std::string panicStringBlob = panicLogContent.get<std::string>(kPanicStringKey, "");
      //VLOG(1) << "Debug: panicStringBlob after JSON get_value: \n" << panicStringBlob;
    
      lines = osquery::split(panicStringBlob, "\n");  // embedded newlines
    }
    catch (const pt::json_parser::json_parser_error& e) {
       VLOG(1) << "Could not parse JSON from " << panicLogFilePath << ": " << e.what();
    }
  // }  // end if-new-macOS
    
  for (auto it = lines.begin(); it != lines.end(); it++) {
    auto line = *it;
    boost::trim(line);

    // Before macOS 11, most lines of the panic log were "KEY : VALUE" even if VALUE contained the ":" character too
    auto toks = osquery::split(line, ":");
    if (toks.size() == 0) {
      VLOG(1) << "Could not parse any key:value pair from the panic log line";
      continue;
    }

    // From here on, toks[0] is the kay of a key:value pair, toks[1] the value
    auto timeTokens = osquery::split(toks[0], " ");
    
    if (timeTokens.size() >= 1 && kDays.count(timeTokens[0]) > 0) {
      r["time"] = line;
    }

    boost::regex rxSpaces("\\s+");

    if (kX86KernelRegisters.count(toks[0]) > 0) {
      auto registerTokens = osquery::split(line, ",");
      if (registerTokens.size() == 0) {
        VLOG(1) << "Could not parse the registers from the panic log at " << panicLogFilePath;
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
    } else if (boost::starts_with(toks[0], "last loaded kext at") &&  // macOS 10.15
               toks.size() == 2) {
      r["last_loaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "last unloaded kext at") &&
               toks.size() == 2) {
      r["last_unloaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
    } else if (boost::starts_with(toks[0], "last started kext at") &&  // macOS 12 equivalent
               toks.size() == 2) {
        r["last_loaded"] = boost::regex_replace(toks[1], rxSpaces, " ");
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
    } else if (boost::starts_with(toks[0], "Process name corresponding to current thread") &&
               std::next(it) != lines.end()) {
      r["name"] = boost::regex_replace(toks[1], rxSpaces, " ");
    }
    else if (kKernelPanicKeys.count(toks[0]) != 0 && toks.size() == 2) {
      // all of the other strings defined at the top of this file
      r[kKernelPanicKeys.at(toks[0])] = toks[1];
    } else {
      //VLOG(1) << "Debug: nothing parsed from this line of the panic log.";
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
