/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <grp.h>
#endif

#include <signal.h>

#if !defined(__FreeBSD__) && !defined(WIN32)
#include <sys/syscall.h>
#include <uuid/uuid.h>
#endif

#ifdef WIN32
#include <WinSock2.h>
#endif

#include <ctime>
#include <sstream>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/dispatcher.h>
#include <osquery/distributed.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#ifdef WIN32
#include "osquery/core/windows/wmi.h"
#endif
#include "osquery/carver/carver.h"
#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/core/utils.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

DECLARE_uint64(alarm_timeout);

/// The path to the pidfile for osqueryd
CLI_FLAG(string,
         pidfile,
         OSQUERY_DB_HOME "/osqueryd.pidfile",
         "Path to the daemon pidfile mutex");

/// Should the daemon force unload previously-running osqueryd daemons.
CLI_FLAG(bool,
         force,
         false,
         "Force osqueryd to kill previously-running daemons");

FLAG(string,
     host_identifier,
     "hostname",
     "Field used to identify the host running osquery (hostname, uuid, "
     "instance, ephemeral, specified)");

// Only used when host_identifier=specified
FLAG(string,
     specified_identifier,
     "",
     "Field used to specify the host_identifier when set to \"specified\"");

FLAG(bool, utc, true, "Convert all UNIX times to UTC");

#ifdef WIN32
struct tm* gmtime_r(time_t* t, struct tm* result) {
  _gmtime64_s(result, t);
  return result;
}

struct tm* localtime_r(time_t* t, struct tm* result) {
  _localtime64_s(result, t);
  return result;
}
#endif

std::string getHostname() {
#ifdef WIN32
  long size = 256;
#else
  static long max_hostname = sysconf(_SC_HOST_NAME_MAX);
  long size = (max_hostname > 255) ? max_hostname + 1 : 256;
#endif

  char* hostname = (char*)malloc(size);
  std::string hostname_string;
  if (hostname != nullptr) {
    memset((void*)hostname, 0, size);
    gethostname(hostname, size - 1);
    hostname_string = std::string(hostname);
    free(hostname);
  }

  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string generateNewUUID() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  return boost::uuids::to_string(uuid);
}

std::string generateHostUUID() {
  std::string hardware_uuid;
#ifdef __APPLE__
  // Use the hardware UUID available on OSX to identify this machine
  uuid_t id;
  // wait at most 5 seconds for gethostuuid to return
  const timespec wait = {5, 0};
  if (gethostuuid(id, &wait) == 0) {
    char out[128] = {0};
    uuid_unparse(id, out);
    hardware_uuid = std::string(out);
  }
#elif WIN32
  WmiRequest wmiUUIDReq("Select UUID from Win32_ComputerSystemProduct");
  std::vector<WmiResultItem>& wmiUUIDResults = wmiUUIDReq.results();
  if (wmiUUIDResults.size() != 0) {
    wmiUUIDResults[0].GetString("UUID", hardware_uuid);
  }
#else
  readFile("/sys/class/dmi/id/product_uuid", hardware_uuid);
#endif

  // We know at least Linux will append a newline.
  hardware_uuid.erase(
      std::remove(hardware_uuid.begin(), hardware_uuid.end(), '\n'),
      hardware_uuid.end());
  boost::algorithm::trim(hardware_uuid);
  if (!hardware_uuid.empty()) {
    // Construct a new string to remove trailing nulls.
    return std::string(hardware_uuid.c_str());
  }

  // Unable to get the hardware UUID, just return a new UUID
  return generateNewUUID();
}

Status getInstanceUUID(std::string& ident) {
  // Lookup the instance identifier (UUID) previously generated and stored.
  auto status =
      getDatabaseValue(kPersistentSettings, "instance_uuid_v1", ident);
  if (ident.size() == 0) {
    // There was no UUID stored in the database, generate one and store it.
    ident = osquery::generateNewUUID();
    return setDatabaseValue(kPersistentSettings, "instance_uuid_v1", ident);
  }

  return status;
}

Status getEphemeralUUID(std::string& ident) {
  if (ident.size() == 0) {
    ident = osquery::generateNewUUID();
  }
  return Status(0, "OK");
}

Status getHostUUID(std::string& ident) {
  // Lookup the host identifier (UUID) previously generated and stored.
  auto status = getDatabaseValue(kPersistentSettings, "host_uuid_v3", ident);
  if (ident.size() == 0) {
    // There was no UUID stored in the database, generate one and store it.
    ident = osquery::generateHostUUID();
    return setDatabaseValue(kPersistentSettings, "host_uuid_v3", ident);
  }
  return status;
}

Status getSpecifiedUUID(std::string& ident) {
  if (FLAGS_specified_identifier.empty()) {
    return Status(1, "No specified identifier for host");
  }
  ident = FLAGS_specified_identifier;
  return Status(0, "OK");
}

std::string getHostIdentifier() {
  static std::string ident;

  Status result(2);
  if (ident.size() == 0) {
    // The identifier has not been set yet.
    if (FLAGS_host_identifier == "uuid") {
      result = getHostUUID(ident);
    } else if (FLAGS_host_identifier == "instance") {
      result = getInstanceUUID(ident);
    } else if (FLAGS_host_identifier == "ephemeral") {
      result = getEphemeralUUID(ident);
    } else if (FLAGS_host_identifier == "specified") {
      result = getSpecifiedUUID(ident);
    }

    if (!result.ok()) {
      // assuming the default of "hostname" as the machine identifier
      // intentionally not set to `ident` because the hostname may change
      // throughout the life of the process and we always want to be using the
      // most current hostname
      return osquery::getHostname();
    } else {
      VLOG(1) << "Using host identifier: " << ident;
    }
  }
  return ident;
}

std::string toAsciiTime(const struct tm* tm_time) {
  if (tm_time == nullptr) {
    return "";
  }

  auto time_str = platformAsctime(tm_time);
  boost::algorithm::trim(time_str);
  return time_str + " UTC";
}

std::string toAsciiTimeUTC(const struct tm* tm_time) {
  size_t epoch = toUnixTime(tm_time);
  struct tm tptr;

  memset(&tptr, 0, sizeof(tptr));

  if (epoch == (size_t)-1) {
    return "";
  }

  gmtime_r((time_t*)&epoch, &tptr);
  return toAsciiTime(&tptr);
}

std::string getAsciiTime() {
  auto result = std::time(nullptr);

  struct tm now;
  gmtime_r(&result, &now);

  return toAsciiTime(&now);
}

size_t toUnixTime(const struct tm* tm_time) {
  struct tm result;
  memset(&result, 0, sizeof(result));

  memcpy(&result, tm_time, sizeof(result));
  return mktime(&result);
}

size_t getUnixTime() {
  return std::time(nullptr);
}

Status checkStalePid(const std::string& content) {
  int pid;
  try {
    pid = boost::lexical_cast<int>(content);
  } catch (const boost::bad_lexical_cast& /* e */) {
    return Status(0, "Could not parse pid from existing pidfile");
  }

  PlatformProcess target(pid);
  int status = 0;

  // The pid is running, check if it is an osqueryd process by name.
  std::stringstream query_text;

  query_text << "SELECT name FROM processes WHERE pid = " << pid
             << " AND name LIKE 'osqueryd%';";

  SQL q(query_text.str());
  if (!q.ok()) {
    return Status(1, "Error querying processes: " + q.getMessageString());
  }

  if (q.rows().size() > 0) {
    // If the process really is osqueryd, return an "error" status.
    if (FLAGS_force) {
      // The caller may choose to abort the existing daemon with --force.
      // Do not use SIGQUIT as it will cause a crash on OS X.
      status = target.kill() ? 0 : -1;
      sleepFor(1000);

      return Status(status, "Tried to force remove the existing osqueryd");
    }

    return Status(1, "osqueryd (" + content + ") is already running");
  } else {
    VLOG(1) << "Found stale process for osqueryd (" << content << ")";
  }

  return Status(0, "OK");
}

Status createPidFile() {
  // check if pidfile exists
  auto pidfile_path = fs::path(FLAGS_pidfile).make_preferred();

  if (pathExists(pidfile_path).ok()) {
    // if it exists, check if that pid is running.
    std::string content;
    auto read_status = readFile(pidfile_path, content, true);
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
    boost::filesystem::remove(pidfile_path);
  } catch (const boost::filesystem::filesystem_error& /* e */) {
    // Unable to remove old pidfile.
    LOG(WARNING) << "Unable to remove the osqueryd pidfile";
  }

  // If no pidfile exists or the existing pid was stale, write, log, and run.
  auto pid = boost::lexical_cast<std::string>(
      PlatformProcess::getCurrentProcess()->pid());
  VLOG(1) << "Writing osqueryd pid (" << pid << ") to "
          << pidfile_path.string();
  auto status = writeTextFile(pidfile_path, pid, 0644);
  return status;
}

bool PlatformProcess::cleanup() const {
  if (!isValid()) {
    return false;
  }

  size_t delay = 0;
  size_t timeout = (FLAGS_alarm_timeout + 1) * 1000;
  while (delay < timeout) {
    int status = 0;
    if (checkStatus(status) == PROCESS_EXITED) {
      return true;
    }

    sleepFor(200);
    delay += 200;
  }
  // The requested process did not exit.
  return false;
}

#ifndef WIN32

bool ownerFromResult(const QueryData& result, long& uid, long& gid) {
  if (result.empty()) {
    return false;
  }

  if (!safeStrtol(result[0].at("uid"), 10, uid) ||
      !safeStrtol(result[0].at("gid"), 10, gid)) {
    return false;
  }
  return true;
}

bool DropPrivileges::dropToParent(const fs::path& path) {
  auto result =
      SQL::selectAllFrom("file", "path", EQUALS, path.parent_path().string());

  long uid = 0;
  long gid = 0;
  if (!ownerFromResult(result, uid, gid)) {
    return false;
  }
  return dropTo(static_cast<uid_t>(uid), static_cast<gid_t>(gid));
}

bool DropPrivileges::dropTo(const std::string& user) {
  auto result = SQL::selectAllFrom("users", "username", EQUALS, user);

  long uid = 0;
  long gid = 0;
  if (!ownerFromResult(result, uid, gid)) {
    return false;
  }
  return dropTo(static_cast<uid_t>(uid), static_cast<gid_t>(gid));
}

bool setThreadEffective(uid_t uid, gid_t gid) {
#if defined(__APPLE__)
  return (pthread_setugid_np(uid, gid) == 0);
#elif defined(__linux__)
  return (syscall(SYS_setresgid, -1, gid, -1) == 0 &&
          syscall(SYS_setresuid, -1, uid, -1) == 0);
#endif
  return 0;
}

bool DropPrivileges::dropTo(uid_t uid, gid_t gid) {
  if (uid == geteuid() && gid == getegid()) {
    // Privileges do not need to be dropped.
    return true;
  } else if (dropped() && uid == to_user_ && gid == to_group_) {
    // Privileges are already dropped to the requested user and group.
    return true;
  } else if (dropped()) {
    return false;
  }

  /// Drop process groups.
  if (original_groups_ != nullptr) {
    restoreGroups();
  }

  group_size_ = getgroups(0, nullptr);
  original_groups_ = (gid_t*)malloc(group_size_ * sizeof(gid_t));
  group_size_ = getgroups(group_size_, original_groups_);
  setgroups(1, &gid);

  if (!setThreadEffective(uid, gid)) {
    (void)setegid(getgid());
    return false;
  }

  // Privileges are now dropped to the requested user/group.
  to_user_ = uid;
  to_group_ = gid;
  dropped_ = true;
  return true;
}

void DropPrivileges::restoreGroups() {
  setgroups(group_size_, original_groups_);
  group_size_ = 0;
  free(original_groups_);
  original_groups_ = nullptr;
}

DropPrivileges::~DropPrivileges() {
  // We are elevating privileges, there is no security vulnerability if
  // either privilege change fails.
  if (dropped_) {
#ifdef __APPLE__
    setThreadEffective(KAUTH_UID_NONE, KAUTH_GID_NONE);
#else
    setThreadEffective(getuid(), getgid());
#endif
    dropped_ = false;
  }

  if (original_groups_ != nullptr) {
    restoreGroups();
  }
}
#endif

Status carvePaths(const std::set<std::string>& paths) {
  auto guid = generateNewUUID();
  pt::ptree tree;
  tree.put("carve_guid", guid);
  tree.put("time", getUnixTime());
  tree.put("status", "STARTING");
  tree.put("sha256", "");
  tree.put("size", -1);
  if (paths.size() > 1) {
    tree.put("path", boost::algorithm::join(paths, ","));
  } else {
    tree.put("path", *(paths.begin()));
  }
  std::ostringstream os;
  pt::write_json(os, tree, false);
  auto s = setDatabaseValue(kCarveDbDomain, kCarverDBPrefix + guid, os.str());
  if (!s.ok()) {
    return s;
  } else {
    auto requestId = Distributed::getCurrentRequestId();
    Dispatcher::addService(std::make_shared<Carver>(paths, guid, requestId));
  }
  return s;
}
}
