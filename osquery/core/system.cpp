/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <grp.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <signal.h>

#if !defined(__FreeBSD__) && !defined(WIN32)
#include <sys/syscall.h>
#include <uuid/uuid.h>
#endif

#ifdef WIN32
#include <WinSock2.h>
#endif

#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif

#if defined(__APPLE__)
#include <sys/kauth.h>
#endif

#include <sstream>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/data_logger.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/sql/sql.h>

#ifdef WIN32
#include "osquery/core/windows/wmi.h"
#endif
#include "osquery/utils/config/default_paths.h"
#include "osquery/utils/conversions/tryto.h"
#include "osquery/utils/info/platform_type.h"
#include "osquery/utils/info/tool_type.h"
#ifdef WIN32
#include <osquery/utils/conversions/windows/strings.h>
#endif

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_uint64(alarm_timeout);

/// The path to the pidfile for osqueryd
CLI_FLAG(string,
         pidfile,
         OSQUERY_PIDFILE "osqueryd.pidfile",
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

namespace {

const std::vector<std::string> kPlaceholderHardwareUUIDList{
    "00000000-0000-0000-0000-000000000000",
    "03000200-0400-0500-0006-000700080009",
    "03020100-0504-0706-0809-0a0b0c0d0e0f",
    "10000000-0000-8000-0040-000000000000",
};

/// The time osquery was started.
std::atomic<uint64_t> kStartTime{0};
} // namespace

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
  long max_path = 256;
  long size = 0;
#ifndef WIN32
  static long max_hostname = sysconf(_SC_HOST_NAME_MAX);
  size = (max_hostname > max_path - 1) ? max_hostname + 1 : max_path;
#endif
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    size = max_path;
  }

  std::vector<char> hostname(size, 0x0);
  std::string hostname_string;
  gethostname(hostname.data(), size - 1);
  hostname_string = std::string(hostname.data());
  boost::algorithm::trim(hostname_string);
  return hostname_string;
}

std::string getFqdn() {
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    std::string fqdn_string = getHostname();

#ifndef WIN32
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(fqdn_string.c_str(), nullptr, &hints, &res) == 0) {
      if (res->ai_canonname != nullptr) {
        fqdn_string = res->ai_canonname;
      }
    }
    if (res != nullptr) {
      freeaddrinfo(res);
    }
#endif
    return fqdn_string;
  } else {
    std::string result;
#ifdef WIN32
    DWORD size = 0;
    if (0 == GetComputerNameExW(ComputerNameDnsFullyQualified, NULL, &size)) {
      std::vector<WCHAR> fqdn(size, 0x0);
      GetComputerNameExW(ComputerNameDnsFullyQualified, fqdn.data(), &size);
      result = wstringToString(fqdn.data());
    }

#endif
    return result;
  }
}

std::string generateNewUUID() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  return boost::uuids::to_string(uuid);
}

bool isPlaceholderHardwareUUID(const std::string& uuid) {
  std::string lower_uuid = boost::to_lower_copy(uuid);

  return std::find(kPlaceholderHardwareUUIDList.begin(),
                   kPlaceholderHardwareUUIDList.end(),
                   lower_uuid) != kPlaceholderHardwareUUIDList.end();
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
  const WmiRequest wmiUUIDReq("Select UUID from Win32_ComputerSystemProduct");
  const std::vector<WmiResultItem>& wmiUUIDResults = wmiUUIDReq.results();
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
    hardware_uuid = std::string(hardware_uuid.c_str());
  }

  // Check whether the UUID is valid. If not generate an ephemeral UUID.
  if (hardware_uuid.empty()) {
    VLOG(1) << "Failed to read system uuid, returning ephemeral uuid";
    return generateNewUUID();
  } else if (isPlaceholderHardwareUUID(hardware_uuid)) {
    VLOG(1) << "Hardware uuid '" << hardware_uuid
            << "' is a placeholder, returning ephemeral uuid";
    return generateNewUUID();
  } else {
    return hardware_uuid;
  }
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
  return Status::success();
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
  return Status::success();
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

Status checkStalePid(const std::string& content) {
  int pid;
  try {
    pid = boost::lexical_cast<int>(content);
  } catch (const boost::bad_lexical_cast& /* e */) {
    return Status::success();
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

  return Status::success();
}

Status createPidFile() {
  // check if pidfile exists
  auto pidfile_path = fs::path(FLAGS_pidfile).make_preferred();

  if (pathExists(pidfile_path).ok()) {
    // if it exists, check if that pid is running.
    std::string content;
    auto read_status = readFile(pidfile_path, content);
    if (!read_status.ok()) {
      return Status(1, "Could not read pidfile: " + read_status.toString());
    }

    auto stale_status = checkStalePid(content);
    if (!stale_status.ok()) {
      return stale_status;
    }
  }

  // Now the pidfile is either the wrong pid or the pid is not running.
  if (!removePath(pidfile_path)) {
    // Unable to remove old pidfile.
    LOG(WARNING) << "Unable to remove the osqueryd pidfile";
  }

  // If no pidfile exists or the existing pid was stale, write, log, and run.
  auto pid = std::to_string(PlatformProcess::getCurrentPid());
  VLOG(1) << "Writing osqueryd pid (" << pid << ") to "
          << pidfile_path.string();
  auto status = writeTextFile(pidfile_path, pid, 0644);
  return status;
}

bool PlatformProcess::cleanup(std::chrono::milliseconds timeout) const {
  if (!isValid()) {
    return false;
  }

  size_t delay = 0;
  while (delay < static_cast<size_t>(timeout.count())) {
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

static inline bool ownerFromResult(const Row& row, long& uid, long& gid) {
  auto const uid_exp = tryTo<long>(row.at("uid"), 10);
  auto const gid_exp = tryTo<long>(row.at("gid"), 10);
  if (uid_exp.isValue()) {
    uid = uid_exp.get();
  }
  if (gid_exp.isValue()) {
    gid = gid_exp.get();
  }
  return uid_exp.isValue() && gid_exp.isValue();
}

DropPrivilegesRef DropPrivileges::get() {
  DropPrivilegesRef handle = DropPrivilegesRef(new DropPrivileges());
  return handle;
}

bool DropPrivileges::dropToParent(const fs::path& path) {
  auto parent = path.parent_path().string();
  auto result = SQL::selectAllFrom("file", "path", EQUALS, parent);
  if (result.empty()) {
    return false;
  }

  if (result.front().at("symlink") == "1") {
    // The file is a symlink, inspect the owner of the link.
    struct stat link_stat;
    if (lstat(parent.c_str(), &link_stat) != 0) {
      return false;
    }

    return dropTo(link_stat.st_uid, link_stat.st_gid);
  }

  long uid = 0;
  long gid = 0;
  if (!ownerFromResult(result.front(), uid, gid)) {
    return false;
  }

  return dropTo(static_cast<uid_t>(uid), static_cast<gid_t>(gid));
}

bool DropPrivileges::dropTo(const std::string& user) {
  auto result = SQL::selectAllFrom("users", "username", EQUALS, user);
  if (result.empty()) {
    return false;
  }

  long uid = 0;
  long gid = 0;
  if (!ownerFromResult(result.front(), uid, gid)) {
    return false;
  }

  return dropTo(static_cast<uid_t>(uid), static_cast<gid_t>(gid));
}

bool setThreadEffective(uid_t uid, gid_t gid) {
#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
  return (pthread_setugid_np(uid, gid) == 0);
#pragma GCC diagnostic pop
#elif defined(__linux__)
  return (syscall(SYS_setresgid, -1, gid, -1) == 0 &&
          syscall(SYS_setresuid, -1, uid, -1) == 0);
#endif
  return 0;
}

bool DropPrivileges::dropTo(const std::string& uid, const std::string& gid) {
  auto const uid_exp = tryTo<uid_t>(uid, 10);
  auto const gid_exp = tryTo<gid_t>(gid, 10);
  if (uid_exp.isError() || gid_exp.isError() ||
      !dropTo(uid_exp.get(), gid_exp.get())) {
    return false;
  }
  return true;
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
  if (group_size_ > 0) {
    original_groups_ = (gid_t*)malloc(group_size_ * sizeof(gid_t));
    group_size_ = getgroups(group_size_, original_groups_);
  }
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
  if (group_size_ > 0) {
    setgroups(group_size_, original_groups_);
    group_size_ = 0;
    free(original_groups_);
  }
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

Status setThreadName(const std::string& name) {
#if defined(__APPLE__)
  int return_code = pthread_setname_np(name.substr(0, 15).c_str());
  return return_code == 0
             ? Status::success()
             : Status::failure("pthread_setname_np failed with error " +
                               std::to_string(return_code));
#elif defined(__linux__)
  int return_code =
      pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
  return return_code == 0
             ? Status::success()
             : Status::failure("pthread_setname_np failed with error " +
                               std::to_string(return_code));
#elif defined(__FreeBSD__)
  // FreeBSD silently ignores errors and does not return an error code
  pthread_set_name_np(pthread_self(), name.substr(0, 15).c_str());
  return Status::success();
#elif defined(WIN32)
  // SetThreadDescription is available in builds newer than 1607 of windows 10
  // and works even if there is no debugger.
  typedef HRESULT(WINAPI * PFNSetThreadDescription)(HANDLE hThread,
                                                    PCWSTR lpThreadDescription);
  auto pfnSetThreadDescription = reinterpret_cast<PFNSetThreadDescription>(
      GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetThreadDescription"));
  if (pfnSetThreadDescription != nullptr) {
    std::wstring wideName{stringToWstring(name)};
    HRESULT hr = pfnSetThreadDescription(GetCurrentThread(), wideName.c_str());
    if (!FAILED(hr)) {
      return Status::success();
    }
  }
  return Status::failure(
      "setThreadName failed due to GetProcAddress returning null");
#else
  return Status::failure("setThreadName not supported on this OS");
#endif
}

void setStartTime(uint64_t st) {
  kStartTime = st;
}

uint64_t getStartTime() {
  return kStartTime;
}

bool checkPlatform(const std::string& platform) {
  if (platform.empty() || platform == "null") {
    return true;
  }

  if (platform.find("any") != std::string::npos ||
      platform.find("all") != std::string::npos) {
    return true;
  }

  // Technically "centos" and "ubuntu" are no longer supported. We have never
  // differentiated between Linux distributions, but rather execute all Linux
  // based queries on any Linux system.
  auto linux_type = (platform.find("linux") != std::string::npos ||
                     platform.find("ubuntu") != std::string::npos ||
                     platform.find("centos") != std::string::npos);
  if (linux_type && isPlatform(osquery::PlatformType::TYPE_LINUX)) {
    return true;
  }

  auto posix_type = (platform.find("posix") != std::string::npos);
  if (posix_type && isPlatform(osquery::PlatformType::TYPE_POSIX)) {
    return true;
  }

  return (platform.find(osquery::kSDKPlatform) != std::string::npos);
}
} // namespace osquery
