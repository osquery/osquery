/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <limits>
#include <memory>

#include <boost/variant.hpp>

#include <osquery/events/eventpublisher.h>
#include <osquery/events/linux/auditdnetlink.h>

namespace osquery {

struct UserAuditEventData final {
  std::uint64_t user_event_id;
};

struct SyscallAuditEventData final {
  std::uint64_t syscall_number;
  bool succeeded;

  pid_t process_id;
  pid_t parent_process_id;

  uid_t process_uid;
  uid_t process_auid;
  uid_t process_euid;
  uid_t process_fsuid;
  uid_t process_suid;

  gid_t process_gid;
  gid_t process_egid;
  gid_t process_fsgid;
  gid_t process_sgid;

  std::string executable_path;
};

struct AppArmorAuditEventData final {
  std::unordered_map<std::string, boost::variant<std::string, std::uint64_t>>
      fields = {{"apparmor", ""},
                {"operation", ""},
                {"profile", ""},
                {"name", ""},
                {"comm", ""},
                {"denied_mask", ""},
                {"capname", ""},
                {"requested_mask", ""},
                {"info", ""},
                {"error", ""},
                {"namespace", ""},
                {"label", ""},
                {"parent", 0},
                {"pid", 0},
                {"capability", 0},
                {"fsuid", 0},
                {"ouid", 0}};
};

/*
   Message example:
   auid=65876 uid=0 gid=0 ses=12684 pid=18204 comm="qemu-system-x86"
   exe="/usr/bin/qemu-system-x86_64" sig=0 arch=c000003e syscall=271 compat=0
   ip=0x7f6ba2cdd811 code=0x7ffc0000
 */
struct SeccompAuditEventData final {
  std::unordered_map<std::string, boost::variant<std::string, std::uint64_t>>
      fields = {{"auid", 0}, // audit user ID (loginuid) of the user who started
                             // the analyzed process
                {"uid", 0}, // user ID
                {"gid", 0}, // group ID
                {"ses", 0}, // session ID
                {"pid", 0}, // process ID

                {"comm", ""}, // command-line name of the command that was
                              // used to invoke the analyzed process

                {"exe", ""}, // the path to the executable that was used
                             // to invoke the analyzed process

                {"sig", 0}, // signal value sent to process by seccomp

                {"arch", 0}, // information about the CPU architecture
                {"syscall", 0}, // type of the system call

                {"compat", 0}, // result of in_compat_syscall()
                               // is system call in compatibility mode

                {"ip", ""}, // result of KSTK_EIP(current)
                            // instruction pointer value

                {"code", 0}}; // the seccomp action
};

/// Audit event descriptor
struct AuditEvent final {
  enum class Type { UserEvent, Syscall, SELinux, AppArmor, Seccomp };

  Type type;
  boost::variant<UserAuditEventData,
                 SyscallAuditEventData,
                 AppArmorAuditEventData,
                 SeccompAuditEventData>
      data;

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
  static void ProcessEvents(
      AuditEventContextRef event_context,
      const std::vector<AuditEventRecord>& record_list,
      AuditTraceContext& trace_context,
      const std::set<int>& syscalls_allowed_to_fail) noexcept;

 private:
  /// Netlink reader
  std::unique_ptr<AuditdNetlink> audit_netlink_;

  /// This is where audit records are assembled
  AuditTraceContext audit_trace_context_;

  /// Syscalls allowed to fail (captured even if success=no)
  std::set<int> syscalls_allowed_to_fail_;
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

// Strips first and last quote from string if present
std::string StripQuotes(const std::string& value) noexcept;

void parseSeccompEvent(const AuditEventRecord& record,
                       SeccompAuditEventData& data) noexcept;
} // namespace osquery
