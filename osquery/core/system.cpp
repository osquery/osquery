// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/database/db_handle.h"

#include <uuid/uuid.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

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

std::string generateNewUuid() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  return boost::uuids::to_string(uuid);
}

std::string generateHostUuid() {
#ifdef __APPLE__
  // Use the hardware uuid available on OSX to identify this machine
  char uuid[128];
  memset(uuid, 0, 128);
  uuid_t id;
  // wait at most 5 seconds for gethostuuid to return
  const timespec wait = {5, 0};
  int result = gethostuuid(id, &wait);
  if (result == 0) {
    char out[128];
    uuid_unparse(id, out);
    std::string uuid_string = std::string(out);
    boost::algorithm::trim(uuid_string);
    return uuid_string;
  } else {
    // unable to get the hardware uuid, just return a new uuid
    return generateNewUuid();
  }
#else
  return generateNewUuid();
#endif
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
