/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <linux/audit.h>
#include <linux/seccomp.h>

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/auditeventpublisher.h>

namespace osquery {

class SeccompEventSubscriber final
    : public EventSubscriber<AuditEventPublisher> {
  /// Mapping from seccomp action codes from seccomp.h to seccomp action names
  static const std::unordered_map<std::uint64_t, std::string>
      seccomp_actions_map;

  /// Mapping from architecture codes from audit.h to architecture names
  static const std::unordered_map<std::uint64_t, std::string> arch_codes_map;

  /// Mapping from system call numbers to system call names for x86_64
  static const std::unordered_map<std::uint64_t, std::string>
      syscall_x86_64_map;

  static void parseEvent(const AuditEvent& event, Row& parsed_event) noexcept;

 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status processEvents(
      QueryData& emitted_row_list,
      const std::vector<AuditEvent>& event_list) noexcept;
};
} // namespace osquery
