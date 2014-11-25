// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/database/db_handle.h"

#include <sys/types.h>
#include <signal.h>

#if !defined(__FreeBSD__)
#include <uuid/uuid.h>
#endif

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <glog/logging.h>

#include "osquery/filesystem.h"
#include "osquery/sql.h"

namespace fs = boost::filesystem;

namespace osquery {

/// The path to the pidfile for osqueryd
DEFINE_osquery_flag(string,
                    pidfile,
                    "/var/osquery/osqueryd.pidfile",
                    "The path to the pidfile for osqueryd.");

std::string getHostname() {
  char hostname[256]; // Linux max should be 64.
  memset(hostname, 0, 256);
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
  auto sql = SQL(
      "SELECT DISTINCT directory FROM users WHERE directory != '/var/empty';");
  std::vector<fs::path> results;
  if (sql.ok()) {
    for (const auto& row : sql.rows()) {
      results.push_back(row.at("directory"));
    }
  } else {
    LOG(ERROR)
        << "Error executing query to return users: " << sql.getMessageString();
  }
  return results;
}

Status createPidFile() {
  // check if pidfile exists
  auto exists = pathExists(FLAGS_pidfile);
  if (exists.ok()) {
    // if it exists, check if that pid is running
    std::string content;
    auto read_status = readFile(FLAGS_pidfile, content);
    if (!read_status.ok()) {
      return Status(1, "Could not read pidfile: " + read_status.toString());
    }
    int osqueryd_pid;
    try {
      osqueryd_pid = stoi(content);
    } catch (const std::invalid_argument& e) {
      return Status(
          1,
          std::string("Could not convert pidfile content to an int: ") +
              std::string(e.what()));
    }

    if (kill(osqueryd_pid, 0) == 0) {
      // if the pid is running, return an "error" status
      return Status(1, "osqueryd is already running");
    } else if (errno == ESRCH) {
      // if the pid isn't running, overwrite the pidfile
      boost::filesystem::remove(FLAGS_pidfile);
      goto write_new_pidfile;
    } else {
      return Status(
          1,
          std::string(
              "An unknown error occured checking if the pid is running: ") +
              std::string(strerror(errno)));
    }
  } else {
  // if it doesn't exist, write a pid file and return a "success" status
  write_new_pidfile:
    auto current_pid = boost::lexical_cast<std::string>(getpid());
    LOG(INFO) << "Writing pid (" << current_pid << ") to " << FLAGS_pidfile;
    auto write_status = writeTextFile(FLAGS_pidfile, current_pid, 0755);
    return write_status;
  }
}
}
