// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <cstring>
#include <ctime>
#include <unistd.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>

#include <glog/logging.h>

#include "osquery/sql.h"

namespace fs = boost::filesystem;

namespace osquery {

std::string getHostname() {
  char hostname[256];
  memset(hostname, 0, 255);
  gethostname(hostname, 255);
  std::string hostname_string = std::string(hostname);
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getAsciiTime() {
  std::time_t result = std::time(NULL);
  std::string time_str = std::string(std::asctime(std::localtime(&result)));
  boost::algorithm::trim(time_str);
  return time_str;
}

int getUnixTime() {
  std::time_t result = std::time(NULL);
  return result;
}

std::vector<fs::path> getHomeDirectories() {
  auto sql = SQL("SELECT DISTINCT directory FROM users WHERE directory != '/var/empty';");
  std::vector<fs::path> results;
  if (sql.ok()) {
    for (const auto& row: sql.rows()) {
      results.push_back(row.at("directory"));
    }
  } else {
    LOG(ERROR) << "Error executing query to return users: " << sql.getMessageString();
  }
  return results;
}
}
