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
#include <AvailabilityMacros.h>
#include <set>
#include <string>
#include <vector>

// Define constants that might be missing in some macOS SDK versions
// We use unique values that won't conflict with actual ES event types

// Network events removed in macOS 15
#ifndef ES_EVENT_TYPE_NOTIFY_SOCKET
#define ES_EVENT_TYPE_NOTIFY_SOCKET ((es_event_type_t)300)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_CONNECT
#define ES_EVENT_TYPE_NOTIFY_CONNECT ((es_event_type_t)301)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_BIND
#define ES_EVENT_TYPE_NOTIFY_BIND ((es_event_type_t)302)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_LISTEN
#define ES_EVENT_TYPE_NOTIFY_LISTEN ((es_event_type_t)303)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_ACCEPT
#define ES_EVENT_TYPE_NOTIFY_ACCEPT ((es_event_type_t)304)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_RECVFROM
#define ES_EVENT_TYPE_NOTIFY_RECVFROM ((es_event_type_t)305)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SENDTO
#define ES_EVENT_TYPE_NOTIFY_SENDTO ((es_event_type_t)306)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_RECVMSG
#define ES_EVENT_TYPE_NOTIFY_RECVMSG ((es_event_type_t)307)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SENDMSG
#define ES_EVENT_TYPE_NOTIFY_SENDMSG ((es_event_type_t)308)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SETSOCKOPT
#define ES_EVENT_TYPE_NOTIFY_SETSOCKOPT ((es_event_type_t)309)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SHUTDOWN
#define ES_EVENT_TYPE_NOTIFY_SHUTDOWN ((es_event_type_t)310)
#endif

// File events removed or missing in some SDKs
#ifndef ES_EVENT_TYPE_NOTIFY_CHMOD
#define ES_EVENT_TYPE_NOTIFY_CHMOD ((es_event_type_t)200)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_CHOWN
#define ES_EVENT_TYPE_NOTIFY_CHOWN ((es_event_type_t)201)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SYMLINK
#define ES_EVENT_TYPE_NOTIFY_SYMLINK ((es_event_type_t)202)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED
#define ES_EVENT_TYPE_NOTIFY_READDIR_EXTENDED ((es_event_type_t)203)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR
#define ES_EVENT_TYPE_NOTIFY_CLONEEXTATTR ((es_event_type_t)204)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_MATERIALIZE
#define ES_EVENT_TYPE_NOTIFY_MATERIALIZE ((es_event_type_t)205)
#endif

// System events removed or missing in some SDKs
#ifndef ES_EVENT_TYPE_NOTIFY_SYSCTL
#define ES_EVENT_TYPE_NOTIFY_SYSCTL ((es_event_type_t)220)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_PTRACE
#define ES_EVENT_TYPE_NOTIFY_PTRACE ((es_event_type_t)221)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_SLEEP
#define ES_EVENT_TYPE_NOTIFY_SLEEP ((es_event_type_t)222)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_WAKE
#define ES_EVENT_TYPE_NOTIFY_WAKE ((es_event_type_t)223)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES
#define ES_EVENT_TYPE_NOTIFY_IOKIT_SET_PROPERTIES ((es_event_type_t)224)
#endif
#ifndef ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL
#define ES_EVENT_TYPE_NOTIFY_ACCESS_CONTROL ((es_event_type_t)225)
#endif

// Authentication events removed or missing in some SDKs
#ifndef ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
#define ES_EVENT_TYPE_NOTIFY_TCC_MODIFY ((es_event_type_t)240)
#endif

namespace osquery {

/**
 * @brief Get the high-level category for a given event type
 *
 * Categories include: process, filesystem, authentication, network, privilege,
 * system, remote, profile, unknown
 *
 * @param event_type The EndpointSecurity event type
 * @return std::string The category as a string
 */
std::string getEventCategory(es_event_type_t event_type);

/**
 * @brief Get the severity level for a given event type
 *
 * Severity levels: high, medium, low
 *
 * @param event_type The EndpointSecurity event type
 * @return std::string The severity level as a string
 */
std::string getEventSeverity(es_event_type_t event_type);

/**
 * @brief Get a human-readable description for a given event type
 *
 * @param event_type The EndpointSecurity event type
 * @return std::string A human-readable description
 */
std::string getEventDescription(es_event_type_t event_type);

/**
 * @brief Get the string name for an event type (for filtering purposes)
 *
 * @param event_type The EndpointSecurity event type
 * @return std::string The name of the event type (e.g., "EXEC", "FORK")
 */
std::string getEventTypeName(es_event_type_t event_type);

/**
 * @brief Parse a comma-separated list of event type names into a set of event
 * types
 *
 * @param event_list A comma-separated list of event type names
 * @return std::set<es_event_type_t> A set of EndpointSecurity event types
 */
std::set<es_event_type_t> parseEventTypes(const std::string& event_list);

/**
 * @brief Get a list of all high severity event types
 *
 * @return std::vector<es_event_type_t> Vector of high severity event types
 */
std::vector<es_event_type_t> getHighSeverityEventTypes();

/**
 * @brief Get a list of all enabled event types based on configuration
 *
 * This function takes into account the following flags:
 * - es_enable_high_severity_only: Only enable high severity events
 * - es_include_events: Comma-separated list of events to include
 * - es_exclude_events: Comma-separated list of events to exclude
 *
 * @return std::vector<es_event_type_t> Vector of enabled event types
 */
std::vector<es_event_type_t> getEnabledEventTypes();

/**
 * @brief Check if an event type is a process-related event
 *
 * @param event_type The EndpointSecurity event type
 * @return bool True if the event is process-related
 */
bool isProcessEvent(es_event_type_t event_type);

/**
 * @brief Check if an event type is a security event (non-process)
 *
 * @param event_type The EndpointSecurity event type
 * @return bool True if the event is a security event
 */
bool isSecurityEvent(es_event_type_t event_type);

/**
 * @brief Check if an event type is available on the current OS version
 *
 * @param event_type The EndpointSecurity event type
 * @return bool True if the event type is available
 */
bool isEventTypeAvailable(es_event_type_t event_type);

/**
 * @brief Get a list of all enabled event types based on detailed configuration
 *
 * This function provides more granular control over enabled events
 * based on multiple configuration parameters
 *
 * @param high_severity_only Enable only high severity events
 * @param include_events Comma-separated list of events to include
 * @param exclude_events Comma-separated list of events to exclude
 * @param enable_process_events Enable process-related events
 * @param enable_file_events Enable file-related events
 * @param enable_network_events Enable network-related events
 * @param enable_authentication_events Enable authentication-related events
 * @return std::vector<es_event_type_t> Vector of enabled event types
 */
std::vector<es_event_type_t> getEnabledEventTypes(
    bool high_severity_only,
    const std::string& include_events,
    const std::string& exclude_events,
    bool enable_process_events,
    bool enable_file_events,
    bool enable_network_events,
    bool enable_authentication_events);

/**
 * @brief Helper function to extract string from an es_string_token_t
 *
 * @param token The string token
 * @return std::string The extracted string
 */
std::string getStringFromToken(const es_string_token_t* token);

} // namespace osquery