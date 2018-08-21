/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/auditeventpublisher.h"

namespace osquery {

class SocketEventSubscriber final
    : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status ProcessEvents(
      std::vector<Row>& emitted_row_list,
      const std::vector<AuditEvent>& event_list) noexcept;

  /// Returns the set of syscalls that this subscriber can handle
  static const std::unordered_set<int>& GetSyscallSet() noexcept;
};

/// Parses an hex-encoded IPv4 address
std::string ip4FromSaddr(const std::string& saddr, ushort offset);

/// Parses an hex-encoded sockaddr structure
bool parseSockAddr(int syscall_number,
                   const std::string& saddr,
                   Row& row,
                   bool& unix_socket);
} // namespace osquery
