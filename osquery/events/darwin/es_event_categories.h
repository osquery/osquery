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
#include <set>
#include <string>
#include <vector>

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

} // namespace osquery