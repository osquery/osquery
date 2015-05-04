/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ctime>
#include <sstream>

#include <sys/types.h>
#include <signal.h>

#if !defined(__FreeBSD__)
#include <uuid/uuid.h>
#endif

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core.h>
#include <osquery/database/db_handle.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

namespace fs = boost::filesystem;

namespace osquery {

/// The path to the pidfile for osqueryd
CLI_FLAG(string,
         pidfile,
         "/var/osquery/osqueryd.pidfile",
         "Path to the daemon pidfile mutex");

/// Should the daemon force unload previously-running osqueryd daemons.
CLI_FLAG(bool,
         force,
         false,
         "Force osqueryd to kill previously-running daemons");

std::string getHostname() {
  char hostname[256]; // Linux max should be 64.
  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname) - 1);
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
  auto result = std::time(nullptr);
  auto time_str = std::string(std::asctime(std::gmtime(&result)));
  boost::algorithm::trim(time_str);
  return time_str + " UTC";
}

int getUnixTime() {
  auto result = std::time(nullptr);
  return result;
}

Status checkStalePid(const std::string& content) {
  int pid;
  try {
    pid = boost::lexical_cast<int>(content);
  } catch (const boost::bad_lexical_cast& e) {
    if (FLAGS_force) {
      return Status(0, "Force loading and not parsing pidfile");
    } else {
      return Status(1, "Could not parse pidfile");
    }
  }

  int status = kill(pid, 0);
  if (status != ESRCH) {
    // The pid is running, check if it is an osqueryd process by name.
    std::stringstream query_text;
    query_text << "SELECT name FROM processes WHERE pid = " << pid
               << " AND name = 'osqueryd';";
    auto q = SQL(query_text.str());
    if (!q.ok()) {
      return Status(1, "Error querying processes: " + q.getMessageString());
    }

    if (q.rows().size() > 0) {
      // If the process really is osqueryd, return an "error" status.
      if (FLAGS_force) {
        // The caller may choose to abort the existing daemon with --force.
        status = kill(pid, SIGQUIT);
        ::sleep(1);

        return Status(status, "Tried to force remove the existing osqueryd");
      }

      return Status(1, "osqueryd (" + content + ") is already running");
    } else {
      LOG(INFO) << "Found stale process for osqueryd (" << content
                << ") removing pidfile";
    }
  }

  return Status(0, "OK");
}

Status createPidFile() {
  // check if pidfile exists
  auto exists = pathExists(FLAGS_pidfile);
  if (exists.ok()) {
    // if it exists, check if that pid is running.
    std::string content;
    auto read_status = readFile(FLAGS_pidfile, content);
    if (!read_status.ok()) {
      return Status(1, "Could not read pidfile: " + read_status.toString());
    }

    auto stale_status = checkStalePid(content);
    if (!stale_status.ok()) {
      return stale_status;
    }
  }

  // Now the pidfile is either the wrong pid or the pid is not running.
  try {
    boost::filesystem::remove(FLAGS_pidfile);
  } catch (boost::filesystem::filesystem_error& e) {
    // Unable to remove old pidfile.
    LOG(WARNING) << "Unable to remove the osqueryd pidfile";
  }

  // If no pidfile exists or the existing pid was stale, write, log, and run.
  auto pid = boost::lexical_cast<std::string>(getpid());
  LOG(INFO) << "Writing osqueryd pid (" << pid << ") to " << FLAGS_pidfile;
  auto status = writeTextFile(FLAGS_pidfile, pid, 0644);
  return status;
}
}
