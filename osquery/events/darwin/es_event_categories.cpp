/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>
#include <vector>

#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/logger/logger.h>

namespace osquery {

// Event Category Maps
// These maps help determine event properties across macOS versions
// Maps event type to its specific category ("process", "file", "network", etc.)
static std::map<es_event_type_t, std::string> kEventCategories = {
    // Process events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "process"},
    {ES_EVENT_TYPE_NOTIFY_FORK, "process"},
    {ES_EVENT_TYPE_NOTIFY_EXIT, "process"},

    // File events
    {ES_EVENT_TYPE_NOTIFY_CREATE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_OPEN, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLONE, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SETATTRLIST, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_FSGETPATH, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_STAT, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHDIR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_GETATTRLIST, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_READLINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_LOOKUP, "filesystem"},

    // Compatibility for removed file events in macOS 15+
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_SYMLINK, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR, "filesystem"},
    {ES_EVENT_TYPE_NOTIFY_MATERIALIZE, "filesystem"},

    // Memory events
    {ES_EVENT_TYPE_NOTIFY_MMAP, "memory"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "memory"},

    // Network events
    {ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "network"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "network"},

    // Network events that may not be available in newer macOS versions
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

    // Authentication events
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SU, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "authentication"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "authentication"},

    // Security/Malware events
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "security"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "security"},

    // System events
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "system"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "system"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "system"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "system"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "system"},
    {ES_EVENT_TYPE_NOTIFY_SLEEP, "system"},
    {ES_EVENT_TYPE_NOTIFY_WAKE, "system"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES, "system"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL, "system"},

    // Privilege events
    {ES_EVENT_TYPE_NOTIFY_SETUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "privilege"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "privilege"}};

// Maps event type to severity level
static std::map<es_event_type_t, std::string> kEventSeverities = {
    // High severity events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "high"},
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "high"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "high"},
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "high"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "high"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "high"},
    {ES_EVENT_TYPE_NOTIFY_SU, "high"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "high"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "high"},

    // Medium severity events
    {ES_EVENT_TYPE_NOTIFY_FORK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CREATE, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OPEN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "medium"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LINK, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MMAP, "medium"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SOCKET, "medium"},
    {ES_EVENT_TYPE_NOTIFY_CONNECT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_BIND, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LISTEN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "medium"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "medium"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "medium"},

    // Low severity events
    {ES_EVENT_TYPE_NOTIFY_EXIT, "low"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, "low"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "low"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "low"},
    {ES_EVENT_TYPE_NOTIFY_CLONE, "low"},
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "low"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "low"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "low"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "low"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "low"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "low"},
    {ES_EVENT_TYPE_NOTIFY_ACCEPT, "low"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "low"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "low"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "low"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "low"}};

// Maps event type to a human-readable event name/description
static std::map<es_event_type_t, std::string> kEventNames = {
    // Process events
    {ES_EVENT_TYPE_NOTIFY_EXEC, "Process execution"},
    {ES_EVENT_TYPE_NOTIFY_FORK, "Process fork"},
    {ES_EVENT_TYPE_NOTIFY_EXIT, "Process exit"},

    // File events
    {ES_EVENT_TYPE_NOTIFY_CREATE, "File created"},
    {ES_EVENT_TYPE_NOTIFY_OPEN, "File opened"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, "File closed"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, "File renamed"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, "File deleted"},
    {ES_EVENT_TYPE_NOTIFY_TRUNCATE, "File truncated"},
    {ES_EVENT_TYPE_NOTIFY_WRITE, "File written"},
    {ES_EVENT_TYPE_NOTIFY_LINK, "File hard-linked"},
    {ES_EVENT_TYPE_NOTIFY_CHMOD, "File permissions changed"},
    {ES_EVENT_TYPE_NOTIFY_CHOWN, "File ownership changed"},
    {ES_EVENT_TYPE_NOTIFY_MOUNT, "Volume mounted"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, "Volume unmounted"},
    {ES_EVENT_TYPE_NOTIFY_SYMLINK, "Symbolic link created"},

    // Authentication events
    {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "Authentication event"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "XProtect malware detected"},
    {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "XProtect malware remediated"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "Login window login"},
    {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "Login window logout"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "Session login"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "Session logout"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "Session locked"},
    {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "Session unlocked"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "SSH login"},
    {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "SSH logout"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "Screen sharing started"},
    {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "Screen sharing ended"},
    {ES_EVENT_TYPE_NOTIFY_SU, "SU command executed"},
    {ES_EVENT_TYPE_NOTIFY_SUDO, "SUDO command executed"},
    {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "Privacy control modified"},

    // Network events
    {ES_EVENT_TYPE_NOTIFY_SOCKET, "Socket created"},
    {ES_EVENT_TYPE_NOTIFY_CONNECT, "Network connection"},
    {ES_EVENT_TYPE_NOTIFY_BIND, "Socket binding"},
    {ES_EVENT_TYPE_NOTIFY_LISTEN, "Socket listening"},
    {ES_EVENT_TYPE_NOTIFY_ACCEPT, "Connection accepted"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "Unix domain socket bound"},
    {ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "Unix domain socket connection"},

    // System events
    {ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "Kernel extension loaded"},
    {ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "Kernel extension unloaded"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "IOKit device opened"},
    {ES_EVENT_TYPE_NOTIFY_SYSCTL, "System control operation"},
    {ES_EVENT_TYPE_NOTIFY_PTRACE, "Process debugging/tracing"},
    {ES_EVENT_TYPE_NOTIFY_SLEEP, "System sleep"},
    {ES_EVENT_TYPE_NOTIFY_WAKE, "System wake"},
    {ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES, "IOKit properties changed"},
    {ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL, "Access control check"},

    // Privilege events
    {ES_EVENT_TYPE_NOTIFY_SETUID, "User ID changed"},
    {ES_EVENT_TYPE_NOTIFY_SETEUID, "Effective user ID changed"},
    {ES_EVENT_TYPE_NOTIFY_SETREUID, "Real/effective user ID changed"},
    {ES_EVENT_TYPE_NOTIFY_SETGID, "Group ID changed"},
    {ES_EVENT_TYPE_NOTIFY_SETEGID, "Effective group ID changed"},
    {ES_EVENT_TYPE_NOTIFY_SETREGID, "Real/effective group ID changed"},

    // Memory events
    {ES_EVENT_TYPE_NOTIFY_MMAP, "Memory mapped"},
    {ES_EVENT_TYPE_NOTIFY_MPROTECT, "Memory protection changed"}};

// Get the category of an event
std::string getEventCategory(es_event_type_t event_type) {
  auto it = kEventCategories.find(event_type);
  if (it != kEventCategories.end()) {
    return it->second;
  }
  return "unknown";
}

// Get the severity of an event
std::string getEventSeverity(es_event_type_t event_type) {
  auto it = kEventSeverities.find(event_type);
  if (it != kEventSeverities.end()) {
    return it->second;
  }
  return "low"; // Default to low severity for unknown events
}

// Get a human-readable name/description for an event
std::string getEventName(es_event_type_t event_type) {
  auto it = kEventNames.find(event_type);
  if (it != kEventNames.end()) {
    return it->second;
  }
  return "Unknown event type";
}

// Check if the current macOS version supports network events
bool osSupportsNetworkEvents() {
  // In macOS 10.15 - 14.x, network events are supported
  if (__builtin_available(macos 10.15, *)) {
    // Check if we're on macOS 15 or newer, where many network events are
    // removed
    if (__builtin_available(macos 15.0, *)) {
      // In macOS 15+, many network events were removed
      // Return false or check for specific remaining events
      VLOG(1) << "Network events functionality is limited on macOS 15+";
      return false;
    }
    return true;
  }
  return false;
}

// Helper to determine if euid/uid fields should be used based on macOS version
bool useEuidFieldsForSetters() {
  // In macOS 12.0+, the field names for setuid/seteuid/etc. were changed from
  // uid to euid
  if (__builtin_available(macos 12.0, *)) {
    return true;
  }
  return false;
}

// Get enabled event types based on OS version and category
std::vector<es_event_type_t> getEnabledEventTypes(const std::string& category) {
  std::vector<es_event_type_t> enabled_events;

  // Process events are always enabled
  if (category == "process" || category == "all") {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_EXEC);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_FORK);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_EXIT);
  }

  // File events
  if (category == "file" || category == "all") {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_CREATE);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_RENAME);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_OPEN);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_CLOSE);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_UNLINK);

    // Add version-specific file events
    if (__builtin_available(macos 15.0, *)) {
      // In macOS 15+, some event types were renamed
      // Use the new event types when available
    } else {
      // Add legacy file events for pre-15.0
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_CHMOD);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_CHOWN);
    }
  }

  // Network events
  if ((category == "network" || category == "all") &&
      osSupportsNetworkEvents()) {
    // Add basic network events
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_BIND);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT);

    // Add pre-15.0 network events if available
    if (!(__builtin_available(macos 15.0, *))) {
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SOCKET);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_CONNECT);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_BIND);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LISTEN);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_ACCEPT);
    }
  }

  // Authentication events
  if ((category == "authentication" || category == "all") &&
      __builtin_available(macos 13.0, *)) {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK);

    // Add SU/SUDO events for macOS 14.0+
    if (__builtin_available(macos 14.0, *)) {
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SU);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SUDO);
    }
  }

  // Security/Malware events
  if ((category == "security" || category == "all") &&
      __builtin_available(macos 13.0, *)) {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED);
  }

  // Memory events
  if ((category == "memory" || category == "all") &&
      __builtin_available(macos 11.0, *)) {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_MMAP);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_MPROTECT);
  }

  // System events
  if (category == "system" || category == "all") {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_KEXTLOAD);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN);

    // Add sysctl event if not on macOS 15+
    if (!(__builtin_available(macos 15.0, *))) {
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SYSCTL);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_PTRACE);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SLEEP);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_WAKE);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES);
      enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL);
    }
  }

  // Privilege events
  if (category == "privilege" || category == "all") {
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETUID);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETEUID);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETREUID);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETGID);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETEGID);
    enabled_events.push_back(ES_EVENT_TYPE_NOTIFY_SETREGID);
  }

  return enabled_events;
}

} // namespace osquery