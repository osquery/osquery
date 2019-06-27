/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/auditeventpublisher.h>

namespace osquery {

class AuditProcessEventSubscriber final
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
  static const std::set<int>& GetSyscallSet() noexcept;
};
} // namespace osquery
