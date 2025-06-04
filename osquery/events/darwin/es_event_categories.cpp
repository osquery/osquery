/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/logger/logger.h>

#include <algorithm>
#include <map>
#include <sstream>
#include <vector>

namespace osquery {

// Flags for event filtering
FLAG(bool,
     es_enable_high_severity_only,
     false,
     "Only enable high severity EndpointSecurity events");

FLAG(string,
     es_include_events,
     "",
     "Comma-separated list of additional EndpointSecurity events to include");

FLAG(string,
     es_exclude_events,
     "",
     "Comma-separated list of EndpointSecurity events to exclude");

namespace {

// Define the process events
const std::set<es_event_type_t> kProcessEvents = {ES_EVENT_TYPE_NOTIFY_EXEC,
                                                  ES_EVENT_TYPE_NOTIFY_FORK,
                                                  ES_EVENT_TYPE_NOTIFY_EXIT};

// Event type to category mapping
const std::map<es_event_type_t, std::string> kEventCategories = {
    // Process events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "process"},
    {ES_EVENT_TYPE_NOTIFY_FORK, "process"},
    {ES_EVENT_TYPE_NOTIFY_EXIT, "process"},

    // File system events
    {ES_EVENT_TYPE_NOTIFY_CREATE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_OPEN, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LOOKUP, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHDIR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SYMLINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLONE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_FCNTL, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_STAT, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_READDIR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_FSGETPATH, "filesystem"},
    // IOKIT_OPEN is in the system category, not filesystem
    {ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SEARCHFS, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SETACL, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHROOT, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_UTIMES, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_GETATTRLIST, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SETATTRLIST, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_MATERIALIZE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_COPYFILE, "filesystem"},

    // Authentication events
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "authentication"},

    // Network events
    {ES_EVENT_TYPE_NOTIFY_SOCKET, "network"},
    {ES_EVENT_TYPE_NOTIFY_CONNECT, "network"},
    {ES_EVENT_TYPE_NOTIFY_BIND, "network"},
    {ES_EVENT_TYPE_NOTIFY_LISTEN, "network"},
    {ES_EVENT_TYPE_NOTIFY_ACCEPT, "network"},
    {ES_EVENT_TYPE_NOTIFY_RECVFROM, "network"},
    {ES_EVENT_TYPE_NOTIFY_SENDTO, "network"},
    {ES_EVENT_TYPE_NOTIFY_RECVMSG, "network"},
    {ES_EVENT_TYPE_NOTIFY_SENDMSG, "network"},
    {ES_EVENT_TYPE_NOTIFY_SETSOCKOPT, "network"},
    {ES_EVENT_TYPE_NOTIFY_SHUTDOWN, "network"},

    // Privilege events
    {ES_EVENT_TYPE_NOTIFY_SETUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "privilege"},

    // System events
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "system"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "system"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "system"},
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "system"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "system"},
    {ES_EVENT_TYPE_NOTIFY_SIGNAL, "system"},
    {ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, "system"},
    {ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "system"},
    {ES_EVENT_TYPE_NOTIFY_TRACE, "system"},
    {ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "system"},
    {ES_EVENT_TYPE_NOTIFY_SLEEP, "system"},
    {ES_EVENT_TYPE_NOTIFY_WAKE, "system"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES, "system"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "system"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "system"},

    // Remote events
    {ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "remote"},

    // Profile events
    {ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, "profile"},
    {ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE, "profile"},

    // XPC events
    {ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, "xpc"},

    // OpenDirectory events (macOS 14+)
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, "directory"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, "directory"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET, "directory"},
    {ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD, "directory"},

    // Other events
    {ES_EVENT_TYPE_NOTIFY_SU, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "authentication"},
    // Using AUTHENTICATION instead of AUTHORIZATION
    //{ES_EVENT_TYPE_NOTIFY_AUTHORIZATION, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "ipc"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "ipc"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL, "system"},
    {ES_EVENT_TYPE_NOTIFY_SETTIME, "system"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "system"},
    {ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, "process"},
    {ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "process"}};

// Event type to severity mapping
const std::map<es_event_type_t, std::string> kEventSeverities = {
    // High severity events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "high"},
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "high"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "high"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "high"},
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "high"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "high"},
    {ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "high"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "high"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "high"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "high"},
    {ES_EVENT_TYPE_NOTIFY_SU, "high"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "high"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "high"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "high"},
    {ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD, "high"},
    // Using AUTHENTICATION instead of AUTHORIZATION
    //{ES_EVENT_TYPE_NOTIFY_AUTHORIZATION, "high"},
    {ES_EVENT_TYPE_NOTIFY_CHROOT, "high"},

    // Medium severity events
    {ES_EVENT_TYPE_NOTIFY_FORK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "medium"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CONNECT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_BIND, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LISTEN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_ACCEPT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SIGNAL, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MATERIALIZE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SETACL, "medium"},
    {ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "medium"},
    {ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, "medium"},
    {ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SLEEP, "medium"},
    {ES_EVENT_TYPE_NOTIFY_WAKE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL, "medium"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SETTIME, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MMAP, "medium"},

    // Low severity events - All others default to low
};

// Event type to string name mapping (for filtering)
const std::map<es_event_type_t, std::string> kEventNames = {
    // Process events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "EXEC"},
    {ES_EVENT_TYPE_NOTIFY_FORK, "FORK"},
    {ES_EVENT_TYPE_NOTIFY_EXIT, "EXIT"},
    {ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, "PTY_CLOSE"},
    {ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "PTY_GRANT"},

    // File system events
    {ES_EVENT_TYPE_NOTIFY_CREATE, "CREATE"},
    {ES_EVENT_TYPE_NOTIFY_OPEN, "OPEN"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, "CLOSE"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "RENAME"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "UNLINK"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "WRITE"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "TRUNCATE"},
    {ES_EVENT_TYPE_NOTIFY_LOOKUP, "LOOKUP"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS, "ACCESS"},
    {ES_EVENT_TYPE_NOTIFY_CHDIR, "CHDIR"},
    {ES_EVENT_TYPE_NOTIFY_LINK, "LINK"},
    {ES_EVENT_TYPE_NOTIFY_SYMLINK, "SYMLINK"},
    {ES_EVENT_TYPE_NOTIFY_CLONE, "CLONE"},
    {ES_EVENT_TYPE_NOTIFY_FCNTL, "FCNTL"},
    {ES_EVENT_TYPE_NOTIFY_STAT, "STAT"},
    {ES_EVENT_TYPE_NOTIFY_READDIR, "READDIR"},
    {ES_EVENT_TYPE_NOTIFY_FSGETPATH, "FSGETPATH"},
    {ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED, "READDIR_EXTENDED"},
    {ES_EVENT_TYPE_NOTIFY_SEARCHFS, "SEARCHFS"},
    {ES_EVENT_TYPE_NOTIFY_SETACL, "SETACL"},
    {ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "SETEXTATTR"},
    {ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "GETEXTATTR"},
    {ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "DELETEEXTATTR"},
    {ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "LISTEXTATTR"},
    {ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR, "CLONEEXTATTR"},
    {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, "EXCHANGEDATA"},
    {ES_EVENT_TYPE_NOTIFY_CHROOT, "CHROOT"},
    {ES_EVENT_TYPE_NOTIFY_UTIMES, "UTIMES"},
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "CHMOD"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "CHOWN"},
    {ES_EVENT_TYPE_NOTIFY_GETATTRLIST, "GETATTRLIST"},
    {ES_EVENT_TYPE_NOTIFY_SETATTRLIST, "SETATTRLIST"},
    {ES_EVENT_TYPE_NOTIFY_MATERIALIZE, "MATERIALIZE"},
    {ES_EVENT_TYPE_NOTIFY_COPYFILE, "COPYFILE"},

    // Authentication events
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "AUTHENTICATION"},
    // Using AUTHENTICATION instead of AUTHORIZATION
    //{ES_EVENT_TYPE_NOTIFY_AUTHORIZATION, "AUTHORIZATION"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "XP_MALWARE_DETECTED"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "XP_MALWARE_REMEDIATED"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "LW_SESSION_LOGIN"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "LW_SESSION_LOGOUT"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "LW_SESSION_LOCK"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "LW_SESSION_UNLOCK"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "SCREENSHARING_ATTACH"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "SCREENSHARING_DETACH"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "OPENSSH_LOGIN"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "OPENSSH_LOGOUT"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "LOGIN_LOGIN"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "LOGIN_LOGOUT"},
    {ES_EVENT_TYPE_NOTIFY_SU, "SU"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "SUDO"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "TCC_MODIFY"},

    // Network events
    {ES_EVENT_TYPE_NOTIFY_SOCKET, "SOCKET"},
    {ES_EVENT_TYPE_NOTIFY_CONNECT, "CONNECT"},
    {ES_EVENT_TYPE_NOTIFY_BIND, "BIND"},
    {ES_EVENT_TYPE_NOTIFY_LISTEN, "LISTEN"},
    {ES_EVENT_TYPE_NOTIFY_ACCEPT, "ACCEPT"},
    {ES_EVENT_TYPE_NOTIFY_RECVFROM, "RECVFROM"},
    {ES_EVENT_TYPE_NOTIFY_SENDTO, "SENDTO"},
    {ES_EVENT_TYPE_NOTIFY_RECVMSG, "RECVMSG"},
    {ES_EVENT_TYPE_NOTIFY_SENDMSG, "SENDMSG"},
    {ES_EVENT_TYPE_NOTIFY_SETSOCKOPT, "SETSOCKOPT"},
    {ES_EVENT_TYPE_NOTIFY_SHUTDOWN, "SHUTDOWN"},

    // Privilege events
    {ES_EVENT_TYPE_NOTIFY_SETUID, "SETUID"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "SETGID"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "SETEUID"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "SETEGID"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "SETREUID"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "SETREGID"},

    // System events
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "MOUNT"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "UNMOUNT"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "IOKIT_OPEN"},
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "KEXTLOAD"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "KEXTUNLOAD"},
    {ES_EVENT_TYPE_NOTIFY_SIGNAL, "SIGNAL"},
    {ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, "CS_INVALIDATED"},
    {ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "PROC_CHECK"},
    {ES_EVENT_TYPE_NOTIFY_TRACE, "TRACE"},
    {ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "PROC_SUSPEND_RESUME"},
    {ES_EVENT_TYPE_NOTIFY_SLEEP, "SLEEP"},
    {ES_EVENT_TYPE_NOTIFY_WAKE, "WAKE"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES, "IOKIT_SET_PROPERTIES"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "SYSCTL"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "PTRACE"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL, "ACCESS_CONTROL"},
    {ES_EVENT_TYPE_NOTIFY_SETTIME, "SETTIME"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "MPROTECT"},

    // Remote events
    {ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "REMOTE_THREAD_CREATE"},

    // Profile events
    {ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, "PROFILE_ADD"},
    {ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE, "PROFILE_REMOVE"},

    // XPC events
    {ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, "XPC_CONNECT"},

    // OpenDirectory events
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, "OD_GROUP_ADD"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, "OD_GROUP_REMOVE"},
    {ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET, "OD_GROUP_SET"},
    {ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD, "OD_MODIFY_PASSWORD"},

    // Other events
    {ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "UIPC_CONNECT"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "UIPC_BIND"},
};

// Reverse mapping for filtering by name
std::map<std::string, es_event_type_t> kEventTypesByName;

// Initialize the reverse mapping
void initializeEventTypesByName() {
  if (kEventTypesByName.empty()) {
    for (const auto& entry : kEventNames) {
      kEventTypesByName[entry.second] = entry.first;
    }
  }
}

} // namespace

std::string getEventCategory(es_event_type_t event_type) {
  auto it = kEventCategories.find(event_type);
  return (it != kEventCategories.end()) ? it->second : "unknown";
}

std::string getEventSeverity(es_event_type_t event_type) {
  auto it = kEventSeverities.find(event_type);
  return (it != kEventSeverities.end()) ? it->second : "low";
}

// Helper function to handle removed/custom event types
std::string getCustomEventDescription(unsigned int event_type_val) {
  // File system events
  if (event_type_val == ES_EVENT_TYPE_NOTIFY_SYMLINK) {
    return "A symbolic link was created";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED) {
    return "Directory contents were read with extended info";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR) {
    return "File extended attributes were cloned";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_CHMOD) {
    return "File permissions were changed";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_CHOWN) {
    return "File ownership was changed";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_MATERIALIZE) {
    return "File was materialized";
  
  // Network events
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SOCKET) {
    return "A socket was created";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_CONNECT) {
    return "A network connection was initiated";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_BIND) {
    return "A socket was bound to an address";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_LISTEN) {
    return "A socket is now listening for connections";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_ACCEPT) {
    return "A connection was accepted";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_RECVFROM) {
    return "Data was received from a socket";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SENDTO) {
    return "Data was sent to a socket";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_RECVMSG) {
    return "Message was received from a socket";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SENDMSG) {
    return "Message was sent to a socket";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SETSOCKOPT) {
    return "Socket option was set";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SHUTDOWN) {
    return "Socket was shut down";
  
  // System events
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SLEEP) {
    return "System is going to sleep";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_WAKE) {
    return "System is waking from sleep";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES) {
    return "IOKit properties were set";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_SYSCTL) {
    return "System control operation was performed";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_PTRACE) {
    return "Process was debugged using ptrace";
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL) {
    return "Access control check was performed";
  
  // Authentication events
  } else if (event_type_val == ES_EVENT_TYPE_NOTIFY_TCC_MODIFY) {
    return "Transparency, Consent, and Control (TCC) database was modified";
  }
  
  return "Unknown custom event type";
}

std::string getEventDescription(es_event_type_t event_type) {
  // First check if this is a custom event type that's been removed in macOS 15+
  unsigned int event_type_val = static_cast<unsigned int>(event_type);
  if ((event_type_val >= 200 && event_type_val <= 240) || 
      (event_type_val >= 300 && event_type_val <= 310)) {
    return getCustomEventDescription(event_type_val);
  }
  
  // Handle standard event types
  switch (event_type) {
  // Process events
  case ES_EVENT_TYPE_NOTIFY_EXEC:
    return "A new process was executed";
  case ES_EVENT_TYPE_NOTIFY_FORK:
    return "A process fork operation occurred";
  case ES_EVENT_TYPE_NOTIFY_EXIT:
    return "A process exit event occurred";
  case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
    return "A pseudo-terminal was closed";
  case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
    return "A pseudo-terminal was granted";

  // File system events
  case ES_EVENT_TYPE_NOTIFY_CREATE:
    return "A file was created";
  case ES_EVENT_TYPE_NOTIFY_OPEN:
    return "A file was opened";
  case ES_EVENT_TYPE_NOTIFY_CLOSE:
    return "A file was closed";
  case ES_EVENT_TYPE_NOTIFY_RENAME:
    return "A file was renamed";
  case ES_EVENT_TYPE_NOTIFY_UNLINK:
    return "A file was deleted";
  case ES_EVENT_TYPE_NOTIFY_WRITE:
    return "A file was written";
  case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
    return "A file was truncated";
  case ES_EVENT_TYPE_NOTIFY_LOOKUP:
    return "A file lookup operation was performed";
  case ES_EVENT_TYPE_NOTIFY_ACCESS:
    return "A file was accessed";
  case ES_EVENT_TYPE_NOTIFY_CHDIR:
    return "Changed current working directory";
  case ES_EVENT_TYPE_NOTIFY_LINK:
    return "A hard link was created";
  case ES_EVENT_TYPE_NOTIFY_CLONE:
    return "A file was cloned";
  case ES_EVENT_TYPE_NOTIFY_FCNTL:
    return "A file control operation was performed";
  case ES_EVENT_TYPE_NOTIFY_STAT:
    return "File status was queried";
  case ES_EVENT_TYPE_NOTIFY_READDIR:
    return "Directory contents were read";
  case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
    return "File system path was retrieved";
  case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
    return "File system search was performed";
  case ES_EVENT_TYPE_NOTIFY_SETACL:
    return "File ACL was modified";
  case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
    return "File extended attribute was set";
  case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
    return "File extended attribute was retrieved";
  case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
    return "File extended attribute was deleted";
  case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
    return "File extended attributes were listed";
  case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
    return "Data was exchanged between files";
  case ES_EVENT_TYPE_NOTIFY_CHROOT:
    return "Process changed root directory";
  case ES_EVENT_TYPE_NOTIFY_UTIMES:
    return "File access and modification times were changed";
  case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
    return "File attribute list was retrieved";
  case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
    return "File attribute list was set";
  case ES_EVENT_TYPE_NOTIFY_COPYFILE:
    return "File was copied";

  // Authentication events
  case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
    return "An authentication event occurred";
  case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
    return "Authorization petition event occurred";
  case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
    return "Authorization judgement event occurred";
  case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
    return "Malware was detected by XProtect";
  case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
    return "Malware was remediated by XProtect";
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
    return "Login window session login";
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
    return "Login window session logout";
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
    return "Login window session lock";
  case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
    return "Login window session unlock";
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
    return "Screen sharing session was attached";
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
    return "Screen sharing session was detached";
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
    return "SSH login event";
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
    return "SSH logout event";
  case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
    return "Login process login event";
  case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
    return "Login process logout event";
  case ES_EVENT_TYPE_NOTIFY_SU:
    return "Switch user (su) command executed";
  case ES_EVENT_TYPE_NOTIFY_SUDO:
    return "Sudo command executed";

  // Privilege events
  case ES_EVENT_TYPE_NOTIFY_SETUID:
    return "Process changed user ID";
  case ES_EVENT_TYPE_NOTIFY_SETGID:
    return "Process changed group ID";
  case ES_EVENT_TYPE_NOTIFY_SETEUID:
    return "Process changed effective user ID";
  case ES_EVENT_TYPE_NOTIFY_SETEGID:
    return "Process changed effective group ID";
  case ES_EVENT_TYPE_NOTIFY_SETREUID:
    return "Process changed real and effective user IDs";
  case ES_EVENT_TYPE_NOTIFY_SETREGID:
    return "Process changed real and effective group IDs";

  // System events
  case ES_EVENT_TYPE_NOTIFY_MOUNT:
    return "A file system was mounted";
  case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
    return "A file system was unmounted";
  case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
    return "An IOKit device was opened";
  case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
    return "A kernel extension was loaded";
  case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
    return "A kernel extension was unloaded";
  case ES_EVENT_TYPE_NOTIFY_SIGNAL:
    return "A signal was sent to a process";
  case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
    return "Code signature was invalidated";
  case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
    return "Process access check was performed";
  case ES_EVENT_TYPE_NOTIFY_TRACE:
    return "Process was traced";
  case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
    return "Process was suspended or resumed";
  case ES_EVENT_TYPE_NOTIFY_SETTIME:
    return "System time was set";
  case ES_EVENT_TYPE_NOTIFY_MPROTECT:
    return "Memory protection was changed";

  // Remote events
  case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
    return "A remote thread was created in another process";

  // Profile events
  case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
    return "A configuration profile was added";
  case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
    return "A configuration profile was removed";

  // XPC events
  case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
    return "A process connected to an XPC service";

  // OpenDirectory events
  case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
    return "User added to OpenDirectory group";
  case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
    return "User removed from OpenDirectory group";
  case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
    return "OpenDirectory group modified";
  case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
    return "OpenDirectory password changed";

  // Other events
  case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
    return "Unix IPC connection established";
  case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
    return "Unix IPC socket binding occurred";

  default:
    return "Unknown event type";
  }
}

std::string getEventTypeName(es_event_type_t event_type) {
  auto it = kEventNames.find(event_type);
  return (it != kEventNames.end()) ? it->second : "UNKNOWN";
}

std::set<es_event_type_t> parseEventTypes(const std::string& event_list) {
  initializeEventTypesByName();

  std::set<es_event_type_t> result;
  if (event_list.empty()) {
    return result;
  }

  std::stringstream ss(event_list);
  std::string event_name;

  while (std::getline(ss, event_name, ',')) {
    // Trim whitespace
    event_name.erase(
        std::remove_if(event_name.begin(),
                       event_name.end(),
                       [](unsigned char c) { return std::isspace(c); }),
        event_name.end());

    // Convert to uppercase for case-insensitive comparison
    std::transform(
        event_name.begin(), event_name.end(), event_name.begin(), ::toupper);

    auto it = kEventTypesByName.find(event_name);
    if (it != kEventTypesByName.end()) {
      result.insert(it->second);
    } else {
      LOG(WARNING) << "Unknown EndpointSecurity event type: " << event_name;
    }
  }

  return result;
}

std::vector<es_event_type_t> getHighSeverityEventTypes() {
  std::vector<es_event_type_t> high_severity_events;

  for (const auto& entry : kEventSeverities) {
    if (entry.second == "high") {
      high_severity_events.push_back(entry.first);
    }
  }

  return high_severity_events;
}

// This is kept only for compatibility with the header, but the actual implementation
// is in es_utils.cpp to avoid duplicate symbol errors at link time
// Do not use this implementation; use the one from es_utils.cpp instead
std::vector<es_event_type_t> getEnabledEventTypes();  // Forward declaration only

bool isProcessEvent(es_event_type_t event_type) {
  return kProcessEvents.find(event_type) != kProcessEvents.end();
}

bool isSecurityEvent(es_event_type_t event_type) {
  return !isProcessEvent(event_type);
}

bool isEventTypeAvailable(es_event_type_t event_type) {
  // Always return true for memory protection events in macOS 15+
  if (event_type == ES_EVENT_TYPE_NOTIFY_MMAP || 
      event_type == ES_EVENT_TYPE_NOTIFY_MPROTECT) {
    return true;
  }
  
  // Check if this event type is in any of our maps
  return (kEventCategories.find(event_type) != kEventCategories.end() ||
          kEventSeverities.find(event_type) != kEventSeverities.end() ||
          kEventNames.find(event_type) != kEventNames.end());
}

std::vector<es_event_type_t> getEnabledEventTypes(
    bool high_severity_only,
    const std::string& include_events,
    const std::string& exclude_events,
    bool enable_process_events,
    bool enable_file_events,
    bool enable_network_events,
    bool enable_authentication_events) {
  
  std::set<es_event_type_t> enabled_events;

  // Always include memory protection events for macOS 15+
  enabled_events.insert(ES_EVENT_TYPE_NOTIFY_MMAP);
  enabled_events.insert(ES_EVENT_TYPE_NOTIFY_MPROTECT);

  // Start with a base set of events (all known events)
  for (const auto& entry : kEventCategories) {
    // Apply category filters
    bool include_by_category = true;
    
    if (!enable_process_events && isProcessEvent(entry.first)) {
      include_by_category = false;
    }
    
    if (!enable_file_events && 
        getEventCategory(entry.first) == "filesystem") {
      include_by_category = false;
    }
    
    if (!enable_network_events && 
        getEventCategory(entry.first) == "network") {
      include_by_category = false;
    }
    
    if (!enable_authentication_events && 
        getEventCategory(entry.first) == "authentication") {
      include_by_category = false;
    }
    
    if (include_by_category) {
      enabled_events.insert(entry.first);
    }
  }

  // Apply high severity only filter if specified
  if (high_severity_only) {
    auto high_severity = getHighSeverityEventTypes();
    std::set<es_event_type_t> high_severity_set(high_severity.begin(),
                                                high_severity.end());

    // Only keep events that are in both sets (intersection)
    std::set<es_event_type_t> filtered_events;
    std::set_intersection(
        enabled_events.begin(),
        enabled_events.end(),
        high_severity_set.begin(),
        high_severity_set.end(),
        std::inserter(filtered_events, filtered_events.begin()));
    enabled_events = filtered_events;
  }

  // Add included events
  if (!include_events.empty()) {
    auto included = parseEventTypes(include_events);
    enabled_events.insert(included.begin(), included.end());
  }

  // Remove excluded events
  if (!exclude_events.empty()) {
    auto excluded = parseEventTypes(exclude_events);
    for (const auto& event : excluded) {
      enabled_events.erase(event);
    }
  }

  return std::vector<es_event_type_t>(enabled_events.begin(),
                                      enabled_events.end());
}

// Function is defined in es_utils.cpp to avoid duplicate symbol errors
std::string getStringFromToken(const es_string_token_t* token);  // Forward declaration only

} // namespace osquery