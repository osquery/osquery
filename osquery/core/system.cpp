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
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
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
#include <osquery/database.h>
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

FLAG(string,
     host_identifier,
     "hostname",
     "Field used to identify the host running osquery (hostname, uuid)");

std::string getHostname() {
  static long max_hostname = sysconf(_SC_HOST_NAME_MAX);
  long size = (max_hostname > 255) ? max_hostname + 1 : 256;
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

std::string generateNewUuid() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  return boost::uuids::to_string(uuid);
}

Status getHostUUID(std::string& ident) {
  // Lookup the host identifier (UUID) previously generated and stored.
  auto status = getDatabaseValue(kPersistentSettings, "hostIdentifier", ident);
  if (ident.size() == 0) {
    // There was no uuid stored in the database, generate one and store it.
    ident = osquery::generateHostUuid();
    VLOG(1) << "Using uuid " << ident << " as host identifier";
    return setDatabaseValue(kPersistentSettings, "hostIdentifier", ident);
  }

  return status;
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

std::string getHostIdentifier() {
  if (FLAGS_host_identifier != "uuid") {
    // use the hostname as the default machine identifier
    return osquery::getHostname();
  }

  // Generate a identifier/UUID for this application launch, and persist.
  static std::string ident;
  if (ident.size() == 0) {
    // Lookup the host identifier (UUID) previously generated and stored.
    getDatabaseValue(kPersistentSettings, "hostIdentifier", ident);
    if (ident.size() == 0) {
      ident = osquery::generateHostUuid();
      VLOG(1) << "Using uuid " << ident << " as host identifier";
      setDatabaseValue(kPersistentSettings, "hostIdentifier", ident);
    }
  }

  return ident;
}

std::string getAsciiTime() {
  auto result = std::time(nullptr);
  auto time_str = std::string(std::asctime(std::gmtime(&result)));
  boost::algorithm::trim(time_str);
  return time_str + " UTC";
}

size_t getUnixTime() {
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
        // Do not use SIGQUIT as it will cause a crash on OS X.
        status = kill(pid, SIGKILL);
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
  } catch (const boost::filesystem::filesystem_error& e) {
    // Unable to remove old pidfile.
    LOG(WARNING) << "Unable to remove the osqueryd pidfile";
  }

  // If no pidfile exists or the existing pid was stale, write, log, and run.
  auto pid = boost::lexical_cast<std::string>(getpid());
  LOG(INFO) << "Writing osqueryd pid (" << pid << ") to " << FLAGS_pidfile;
  auto status = writeTextFile(FLAGS_pidfile, pid, 0644);
  return status;
}

#if defined(__linux__)
#include <sys/fsuid.h>
static inline int _fs_set_group(gid_t gid) { return setfsgid(gid) * 0; }
static inline int _fs_set_user(uid_t uid) { return setfsuid(uid) * 0; }
#else
static inline int _fs_set_group(gid_t gid) { return setegid(gid); }
static inline int _fs_set_user(uid_t uid) { return seteuid(uid); }
#endif

bool DropPrivileges::dropToParent(const fs::path& path) {
  uid_t to_user{0};
  gid_t to_group{0};
  // Open the parent path of the requested file to operate on.
  int pfd = open(path.parent_path().string().c_str(), O_RDONLY | O_NONBLOCK);
  if (pfd >= 0) {
    struct stat file;
    if (geteuid() == 0 && fstat(pfd, &file) >= 0 &&
        (file.st_uid != 0 || file.st_gid != 0)) {
      // A drop is required if this process is executed as a superuser and
      // the folder can be altered by non-super users.
      to_user = file.st_uid;
      to_group = file.st_gid;
    }
    close(pfd);
  }

  if (to_user == 0 && to_group == 0) {
    // No drop required.
    return true;
  } else if (dropped() && to_user == to_user_ && to_group == to_group_) {
    // They are already dropped to the correct user/group.
    return true;
  } else if (!dropped()) {
    // Privileges should be dropped.
    if (_fs_set_group(to_group) != 0) {
      return false;
    } else if (_fs_set_user(to_user) != 0) {
      // Privileges are not dropped and could not be set for the user.
      // Restore the group and fail.
      (void)_fs_set_group(getgid());
      return false;
    }

    // Privileges are now dropped to the requested user/group.
    to_user_ = to_user;
    to_group_ = to_group;
    dropped_ = true;
    fs_drop_ = true;
    return true;
  }

  // Privileges are dropped but not to the requested user/group.
  // Proceed with extreme caution.
  return false;
}

bool DropPrivileges::dropTo(uid_t uid, gid_t gid) {
  if (dropped() && uid == to_user_ && gid == to_group_) {
    // Privileges are already dropped to the requested user and group.
    return true;
  } else if (dropped()) {
    return false;
  }
  /// Drop process groups.
  original_groups_ = (gid_t*)malloc(NGROUPS_MAX * sizeof(gid_t));
  group_size_ = getgroups(NGROUPS_MAX, original_groups_);
  setgroups(1, &gid);
  if (setegid(gid) != 0) {
    return false;
  } else if (seteuid(uid) != 0) {
    (void)setegid(getgid());
    return false;
  }

  // Privileges are now dropped to the requested user/group.
  to_user_ = uid;
  to_group_ = gid;
  dropped_ = true;
  return true;
}

DropPrivileges::~DropPrivileges() {
  if (dropped_) {
    // 1. On Linux/BSD we do not need to differentiate between FS/E since FS
    // is set implicitly by seteuid.
    // 2. We are elevating privileges, there is no security vulnerability if
    // either privilege change fails.
    if (fs_drop_) {
      (void)_fs_set_user(getuid());
      (void)_fs_set_group(getgid());
    } else {
      (void)seteuid(getuid());
      (void)setegid(getgid());
    }
    dropped_ = false;
  }

  if (original_groups_ != nullptr) {
    setgroups(group_size_, original_groups_);
    group_size_ = 0;
    free(original_groups_);
    original_groups_ = nullptr;
  }
}
}
