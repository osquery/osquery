/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/logger/logger.h>
#include <sys/socket.h>

namespace osquery {

// Map of event names to event types for EndpointSecurity
extern std::map<std::string, es_event_type_t> kESEventNameMap;

// Get all enabled EndpointSecurity event types based on configuration
std::vector<es_event_type_t> getEnabledEventTypes();

std::string getEsNewClientErrorMessage(const es_new_client_result_t r);
std::string getPath(const es_process_t* p);
std::string getSigningId(const es_process_t* p);
std::string getTeamId(const es_process_t* p);
std::string getStringFromToken(es_string_token_t* t);
std::string getStringFromToken(const es_string_token_t* t);
std::string getCwdPathFromPid(pid_t pid);
std::string getCDHash(const es_process_t* p);
void getProcessProperties(const es_process_t* p,
                          const EndpointSecurityEventContextRef& ec);
void appendQuotedString(std::ostream& out, std::string s, char delim);

/**
 * @brief Convert socket domain/family value to a human-readable string
 *
 * @param domain The socket domain value (e.g., AF_INET, AF_INET6, AF_UNIX)
 * @return std::string Human-readable description of the socket domain
 */
std::string getSocketDomainDescription(int domain);

/**
 * @brief Convert socket type value to a human-readable string
 *
 * @param type The socket type value (e.g., SOCK_STREAM, SOCK_DGRAM)
 * @return std::string Human-readable description of the socket type
 */
std::string getSocketTypeDescription(int type);

/**
 * @brief Convert socket protocol value to a human-readable string
 *
 * @param protocol The socket protocol value (e.g., IPPROTO_TCP, IPPROTO_UDP)
 * @return std::string Human-readable description of the socket protocol
 */
std::string getSocketProtocolDescription(int protocol);

/**
 * @brief Get category name as string for an ES event type
 *
 * @param event_type ES event type
 * @return std::string Category name
 */
std::string getEventCategoryString(es_event_type_t event_type);

/**
 * @brief Get severity level as string for an ES event type
 *
 * @param event_type ES event type
 * @return std::string Severity level
 */
std::string getEventSeverityString(es_event_type_t event_type);

/**
 * @brief Get human-readable event description
 *
 * @param event_name Event name string (e.g., "exec", "connect", etc.)
 * @param metadata Additional metadata for enhanced description
 * @return std::string Human-readable description
 */
std::string getEventDescription(
    const std::string& event_name,
    const std::map<std::string, std::string>& metadata);

} // namespace osquery
