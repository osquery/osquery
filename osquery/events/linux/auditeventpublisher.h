/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <cstdint>
#include <limits>
#include <memory>

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

  uid_t process_uid;
  uid_t process_euid;

  gid_t process_gid;
  gid_t process_egid;

  std::string executable_path;
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

  /// Executable path
  static std::string executable_path_;

  /// Aggregates raw event records into audit events
  static void ProcessEvents(AuditEventContextRef event_context,
                            const std::vector<AuditEventRecord>& record_list,
                            AuditTraceContext& trace_context) noexcept;

 private:
  /// Netlink reader
  std::unique_ptr<AuditdNetlink> audit_netlink_;

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

/// Copies a named field from the 'fields' map to the specified row
void CopyFieldFromMap(
    Row& row,
    const std::map<std::string, std::string>& fields,
    const std::string& name,
    const std::string& default_value = std::string()) noexcept;
} // namespace osquery
