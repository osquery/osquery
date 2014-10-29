// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

const std::string kSystemCron = "/etc/crontab";

#ifdef __APPLE__
const std::string kUserCronsPath = "/var/at/tabs/";
#else
const std::string kUserCronsPath = "/var/spool/cron/crontabs/";
#endif

std::vector<std::string> cronFromFile(const std::string& path) {
  std::string content;
  std::vector<std::string> cron_lines;
  if (!readFile(path, content).ok()) {
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

  results.push_back(r);
}

QueryData genCronTab() {
  QueryData results;

  auto system_lines = cronFromFile(kSystemCron);
  for (const auto& line : system_lines) {
    genCronLine(kSystemCron, line, results);
  }

  std::vector<std::string> user_crons;
  auto status = listFilesInDirectory(kUserCronsPath, user_crons);
  if (!status.ok()) {
    LOG(ERROR) << "Could not list user crons from: " << kUserCronsPath << " ("
               << status.what() << ")";
    return results;
  }

  // The user-based crons are identified by their path.
  for (const auto& user_path : user_crons) {
    auto user_lines = cronFromFile(user_path);
    for (const auto& line : user_lines) {
      genCronLine(user_path, line, results);
    }
  }

  return results;
}
}
}
