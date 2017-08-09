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

#include <cstdint>
#include <limits>

#include <boost/variant.hpp>

#include <osquery/events.h>

#include "osquery/events/linux/auditdnetlink.h"

namespace osquery {

struct UserAuditEventData final {
  std::uint64_t user_event_id;
};

struct SyscallAuditEventData final {
  std::uint64_t syscall_number;

  pid_t process_id;
  pid_t parent_process_id;
};

/// Audit event descriptor
struct AuditEvent final {
  enum class Type { UserEvent, Syscall };

  Type type;
  boost::variant<UserAuditEventData, SyscallAuditEventData> data;

  std::vector<AuditEventRecord> record_list;
};

/// Audit event pretty printer, used for the --audit_fim_debug flag
std::ostream& operator<<(std::ostream& stream, const AuditEvent& audit_event);

struct AuditSubscriptionContext final : public SubscriptionContext {
 private:
  friend class AuditEventPublisher;
};

struct AuditEventContext final : public EventContext {
  std::vector<AuditEvent> audit_events;
};

using AuditEventContextRef = std::shared_ptr<AuditEventContext>;
using AuditSubscriptionContextRef = std::shared_ptr<AuditSubscriptionContext>;

/// This type maps audit event id with the corresponding audit event object
using AuditTraceContext = std::map<std::string, AuditEvent>;

class AuditEventPublisher final
    : public EventPublisher<AuditSubscriptionContext, AuditEventContext> {
  DECLARE_PUBLISHER("auditeventpublisher");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  virtual ~AuditEventPublisher() {
    tearDown();
  }

  /// Aggregates raw event records into audit events
  static void ProcessEvents(AuditEventContextRef event_context,
                            const std::vector<AuditEventRecord>& record_list,
                            AuditTraceContext& trace_context) noexcept;

 private:
  /// Audit netlink subscription handle
  NetlinkSubscriptionHandle audit_netlink_subscription_{0};

  /// This is where audit records are assembled
  AuditTraceContext audit_trace_context_;
};

/// Extracts the specified audit event record from the given audit event
const AuditEventRecord* GetEventRecord(const AuditEvent& event,
                                       int record_type) noexcept;

/// Extracts the specified string key from the given string map
bool GetStringFieldFromMap(
    std::string& value,
    const std::map<std::string, std::string>& fields,
    const std::string& name,
    const std::string& default_value = std::string()) noexcept;

/// Extracts the specified integer key from the given string map
bool GetIntegerFieldFromMap(
    std::uint64_t& value,
    const std::map<std::string, std::string>& field_map,
    const std::string& field_name,
    std::size_t base = 10,
    std::uint64_t default_value =
        std::numeric_limits<std::uint64_t>::max()) noexcept;
}
