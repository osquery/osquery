/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

/**
 * @brief ESSecurityEventSubscriber is responsible for subscribing to all
 *        security-related EndpointSecurity events (non-process events).
 */
class ESSecurityEventSubscriber
    : public EventSubscriber<EndpointSecurityEventPublisher> {
 public:
  Status init() override;

  /**
   * @brief Processes an EndpointSecurity event and extracts the relevant
   *        fields based on the event type.
   *
   * @param ec The EndpointSecurity event context
   * @param data Additional data passed from the publisher
   */
  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc);

  /**
   * @brief Generates the table rows for the es_security_events table.
   *
   * @param results The output parameter to which the rows are appended
   * @param start Optional start time
   * @param end Optional end time
   * @return Status indicating success or failure
   */
  Status genTable(TableRows& results, QueryContext& context);

  /// The ESProcessEventSubscriber name.
  static const std::string name;

 private:
  /**
   * @brief Adds common fields to the row that are present in all events.
   *
   * @param ec The EndpointSecurity event context
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addCommonFields(Row& r,
                       const EndpointSecurityEventContextRef& ec,
                       const es_message_t* es_message);

  /**
   * @brief Adds fields specific to authentication-related events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addAuthenticationFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to network-related events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addNetworkFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to file system-related events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addFileSystemFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to privilege-related events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addPrivilegeFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to system-related events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addSystemFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to screen sharing events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addScreenSharingFields(Row& r, const es_message_t* es_message);

  /**
   * @brief Adds fields specific to profile events.
   *
   * @param r The event row to add fields to
   * @param es_message The EndpointSecurity message
   */
  void addProfileFields(Row& r, const es_message_t* es_message);
};

} // namespace osquery