/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <EndpointSecurity/EndpointSecurity.h>
#include <string>
#include <vector>

namespace osquery {

// Define polyfills for removed constants with unique values
// These constants are either removed in newer macOS versions or
// may not be available in the SDK based on the build environment

// Network Events
#ifndef ES_EVENT_TYPE_NOTIFY_SOCKET
#define ES_EVENT_TYPE_NOTIFY_SOCKET ((es_event_type_t)200)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_CONNECT
#define ES_EVENT_TYPE_NOTIFY_CONNECT ((es_event_type_t)201)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_BIND
#define ES_EVENT_TYPE_NOTIFY_BIND ((es_event_type_t)202)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_LISTEN
#define ES_EVENT_TYPE_NOTIFY_LISTEN ((es_event_type_t)203)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_ACCEPT
#define ES_EVENT_TYPE_NOTIFY_ACCEPT ((es_event_type_t)204)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_RECVFROM
#define ES_EVENT_TYPE_NOTIFY_RECVFROM ((es_event_type_t)205)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SENDTO
#define ES_EVENT_TYPE_NOTIFY_SENDTO ((es_event_type_t)206)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_RECVMSG
#define ES_EVENT_TYPE_NOTIFY_RECVMSG ((es_event_type_t)207)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SENDMSG
#define ES_EVENT_TYPE_NOTIFY_SENDMSG ((es_event_type_t)208)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SETSOCKOPT
#define ES_EVENT_TYPE_NOTIFY_SETSOCKOPT ((es_event_type_t)209)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SHUTDOWN
#define ES_EVENT_TYPE_NOTIFY_SHUTDOWN ((es_event_type_t)210)
#endif

// File System Events
#ifndef ES_EVENT_TYPE_NOTIFY_CHMOD
#define ES_EVENT_TYPE_NOTIFY_CHMOD ((es_event_type_t)220)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_CHOWN
#define ES_EVENT_TYPE_NOTIFY_CHOWN ((es_event_type_t)221)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SYMLINK
#define ES_EVENT_TYPE_NOTIFY_SYMLINK ((es_event_type_t)222)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED
#define ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED ((es_event_type_t)223)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR
#define ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR ((es_event_type_t)224)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_MATERIALIZE
#define ES_EVENT_TYPE_NOTIFY_MATERIALIZE ((es_event_type_t)225)
#endif

// System Events
#ifndef ES_EVENT_TYPE_NOTIFY_SYSCTL
#define ES_EVENT_TYPE_NOTIFY_SYSCTL ((es_event_type_t)230)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_PTRACE
#define ES_EVENT_TYPE_NOTIFY_PTRACE ((es_event_type_t)231)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_SLEEP
#define ES_EVENT_TYPE_NOTIFY_SLEEP ((es_event_type_t)232)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_WAKE
#define ES_EVENT_TYPE_NOTIFY_WAKE ((es_event_type_t)233)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES
#define ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES ((es_event_type_t)234)
#endif

#ifndef ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL
#define ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL ((es_event_type_t)235)
#endif

// Authentication Events
#ifndef ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
#define ES_EVENT_TYPE_NOTIFY_TCC_MODIFY ((es_event_type_t)240)
#endif

// Helper function to check if an event type is available on current macOS
// version
inline bool isEventTypeAvailable(es_event_type_t event_type) {
  // Memory protection events are always available in macOS 11+
  if (__builtin_available(macos 11.0, *)) {
    if (event_type == ES_EVENT_TYPE_NOTIFY_MMAP ||
        event_type == ES_EVENT_TYPE_NOTIFY_MPROTECT) {
      return true;
    }
  }

  // Authentication events are available in macOS 13+
  if (__builtin_available(macos 13.0, *)) {
    if (event_type == ES_EVENT_TYPE_NOTIFY_AUTHENTICATION ||
        event_type == ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED ||
        event_type == ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED ||
        event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN ||
        event_type == ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT ||
        event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN ||
        event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT ||
        event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK ||
        event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK ||
        event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN ||
        event_type == ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT ||
        event_type == ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH ||
        event_type == ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH) {
      return true;
    }
  }

  // SU/SUDO events are available in macOS 14+
  if (__builtin_available(macos 14.0, *)) {
    if (event_type == ES_EVENT_TYPE_NOTIFY_SU ||
        event_type == ES_EVENT_TYPE_NOTIFY_SUDO) {
      return true;
    }
  }

  // For custom/polyfill event types, check if they're within our defined ranges
  if ((event_type >= 200 && event_type < 300)) {
    // These are our custom polyfill event types
    return false;
  }

  // For basic events available in all versions
  return (event_type == ES_EVENT_TYPE_NOTIFY_EXEC ||
          event_type == ES_EVENT_TYPE_NOTIFY_FORK ||
          event_type == ES_EVENT_TYPE_NOTIFY_EXIT);
}

// Get the category of an event
std::string getEventCategory(es_event_type_t event_type);

// Get the severity of an event
std::string getEventSeverity(es_event_type_t event_type);

// Get a human-readable name/description for an event
std::string getEventName(es_event_type_t event_type);

// Check if the current macOS version supports network events
bool osSupportsNetworkEvents();

// Helper to determine if euid/uid fields should be used based on macOS version
bool useEuidFieldsForSetters();

// Get enabled event types based on OS version and category
std::vector<es_event_type_t> getEnabledEventTypes(const std::string& category);

} // namespace osquery