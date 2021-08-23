/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/auditeventpublisher.h>

namespace osquery {

class SocketEventSubscriber final
    : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status ProcessEvents(std::vector<Row>& emitted_row_list,
                              const std::vector<AuditEvent>& event_list,
                              bool allow_failed_socket_events,
                              bool allow_unix_socket_events,
                              bool allow_null_accept_events,
                              bool allow_null_accept_socket_events) noexcept;

  /// Returns the set of syscalls that this subscriber can handle
  static const std::set<int>& GetSyscallSet() noexcept;

  /// Parses the "saddr" field of an AUDIT_SOCKADDR record
  static bool parseSockAddr(const std::string& saddr,
                            Row& row,
                            bool& unix_socket);
};

} // namespace osquery
