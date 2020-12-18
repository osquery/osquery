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

  /// Processes the execve/execveat event data
  static Status ProcessExecveEventData(Row& row,
                                       const AuditEvent& event) noexcept;

  /// Acquires the ppid and pid fields from the given event record
  static Status GetProcessIDs(std::uint64_t& parent_process_id,
                              std::uint64_t& process_id,
                              int syscall_nr,
                              const AuditEventRecord& syscall_record) noexcept;

  /// Returns true if the given clone() system call contains the CLONE_THREAD
  /// flag
  static Status IsThreadClone(bool& is_thread_clone,
                              int syscall_nr,
                              const AuditEventRecord& syscall_record) noexcept;

  /// Returns the given syscall name
  static bool GetSyscallName(std::string& name, int syscall_nr) noexcept;

  /// Returns the syscall name map
  static const std::unordered_map<int, std::string>&
  GetSyscallNameMap() noexcept;
};
} // namespace osquery
