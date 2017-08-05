/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/events.h>

#include "osquery/events/linux/auditdnetlink.h"

namespace osquery {

/// Syscall event descriptor
struct SyscallMonitorEvent final {
  std::uint64_t syscall_number;
  pid_t process_id;
  pid_t parent_process_id;

  std::vector<AuditEventRecord> record_list;
};

/// Syscall event pretty printer, used for the --audit_fim_debug flag
std::ostream& operator<<(std::ostream& stream,
                         const SyscallMonitorEvent& syscall_event);

struct SyscallMonitorSubscriptionContext final : public SubscriptionContext {
 private:
  friend class SyscallMonitorEventPublisher;
};

struct SyscallMonitorEventContext final : public EventContext {
  std::vector<SyscallMonitorEvent> syscall_events;
};

using SyscallMonitorEventContextRef = std::shared_ptr<SyscallMonitorEventContext>;
using SyscallMonitorSubscriptionContextRef =
    std::shared_ptr<SyscallMonitorSubscriptionContext>;

/// This type maps audit event id with the corresponding syscall event object
using SyscallMonitorTraceContext = std::map<std::string, SyscallMonitorEvent>;

class SyscallMonitorEventPublisher final
    : public EventPublisher<SyscallMonitorSubscriptionContext,
                            SyscallMonitorEventContext> {
  DECLARE_PUBLISHER("syscallmonitor");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  virtual ~SyscallMonitorEventPublisher() {
    tearDown();
  }

  /// Aggregates raw event records into syscall events
  static void ProcessEvents(SyscallMonitorEventContextRef event_context,
                            const std::vector<AuditEventRecord>& record_list,
                            SyscallMonitorTraceContext& trace_context) noexcept;

 private:
  /// Audit netlink subscription handle
  NetlinkSubscriptionHandle audit_netlink_subscription_{0};

  /// This is where audit records are assembled
  SyscallMonitorTraceContext syscall_trace_context_;
};
}
