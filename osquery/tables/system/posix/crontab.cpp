/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

const std::string kSystemCron = "/etc/crontab";

const std::vector<std::string> kCronSearchDirs = {
    "/etc/cron.d/", // system all
    "/var/at/tabs/", // user mac:lion
    "/var/spool/cron/", // user linux:centos
    "/var/spool/cron/crontabs/", // user linux:debian
};

std::vector<std::string> cronFromFile(const std::string& path) {
  std::string content;
  std::vector<std::string> cron_lines;
  if (!isReadable(path).ok()) {
    return cron_lines;
  }

  if (!forensicReadFile(path, content).ok()) {
    return cron_lines;
  }

  auto lines = split(content, "\n");

  // Only populate the lines that are not comments or blank.
  for (auto& line : lines) {
    // Cheat and use a non-const iteration, to inline trim.
    boost::trim(line);
    if (line.size() > 0 && line.at(0) != '#') {
      cron_lines.push_back(line);
    }
  }

  return cron_lines;
}

void genCronLine(const std::string& path,
                 const std::string& line,
                 QueryData& results) {
  Row r;

  r["path"] = path;
  auto columns = split(line, " \t");

  size_t index = 0;
  auto iterator = columns.begin();
  for (; iterator != columns.end(); ++iterator) {
    if (index == 0) {
      if ((*iterator).at(0) == '@') {
        // If the first value is an 'at' then skip to the command.
        r["event"] = *iterator;
        index = 5;
        continue;
      }
      r["minute"] = *iterator;
    } else if (index == 1) {
      r["hour"] = *iterator;
    } else if (index == 2) {
      r["day_of_month"] = *iterator;
    } else if (index == 3) {
      r["month"] = *iterator;
    } else if (index == 4) {
      r["day_of_week"] = *iterator;
    } else if (index == 5) {
      r["command"] = *iterator;
    } else {
      // Long if switch to handle command breaks from space delim.
      r["command"] += " " + *iterator;
    }
    index++;
  }

  if (r["command"].size() == 0) {
    // The line was not well-formed, perhaps it was a variable?
    return;
  }

  results.push_back(r);
}

QueryData genCronTab(QueryContext& context) {
  QueryData results;
  std::vector<std::string> file_list;

  file_list.push_back(kSystemCron);

  for (const auto cron_dir : kCronSearchDirs) {
    osquery::listFilesInDirectory(cron_dir, file_list);
  }

  for (const auto& file_path : file_list) {
    auto lines = cronFromFile(file_path);
    for (const auto& line : lines) {
      genCronLine(file_path, line, results);
    }
  }

  return results;
}
}
}
