#pragma once

#include "osquery/events/linux/auditnetlink.h"
#include <osquery/events.h>

namespace osquery {

/// Syscall event descriptor
struct SyscallEvent final {
  /// Event type
  enum class Type {
    Execve,
    Exit,
    Exit_group,
    Open,
    Openat,
    Open_by_handle_at,
    Close,
    Dup,
    Read,
    Write,
    Mmap,
    Invalid
  };

  //
  // Populated from the AUDIT_SYSCALL event record
  //

  /// Event type
  Type type;

  /// Process id
  __pid_t process_id;

  /// Parent process id
  __pid_t parent_process_id;

  /// Input file descriptor (i.e.: read syscall)
  int input_fd;

  /// Output file descriptor (i.e.: open syscall)
  int output_fd;

  /// Syscall exit status
  std::string success;

  /// Executable path
  std::string executable_path;

  /// Memory protection flags (only valid for mmap() calls)
  int mmap_memory_protection_flags;

  /// If true, this is a partial event
  bool partial;

  //
  // Populated from the AUDIT_CWD event record
  //

  /// Working directory at the time of the syscall
  std::string cwd;

  //
  // Populated from the AUDIT_PATH event record
  //

  /// Path passed to the syscall
  std::string path;
};

/// Syscall event pretty printer, used for the --audit_fim_debug flag
std::ostream& operator<<(std::ostream& stream,
                         const SyscallEvent& syscall_event);

struct AuditFimSubscriptionContext : public SubscriptionContext {
  bool dummy;

 private:
  friend class AuditFimEventPublisher;
};

struct AuditFimEventContext : public EventContext {
  std::vector<SyscallEvent> syscall_events;
};

using AuditFimEventContextRef = std::shared_ptr<AuditFimEventContext>;
using AuditFimSubscriptionContextRef =
    std::shared_ptr<AuditFimSubscriptionContext>;

class AuditFimEventPublisher
    : public EventPublisher<AuditFimSubscriptionContext, AuditFimEventContext> {
  DECLARE_PUBLISHER("auditfim");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

 public:
  AuditFimEventPublisher() : EventPublisher() {}

  virtual ~AuditFimEventPublisher() {
    tearDown();
  }

 private:
  /// Audit netlink subscription handle
  NetlinkSubscriptionHandle audit_netlink_subscription_;

  /// This is where audit records are assembled
  std::map<std::string, SyscallEvent> syscall_event_list_;
};
}
