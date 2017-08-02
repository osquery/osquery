#pragma once

#include "osquery/events/linux/auditdnetlink.h"
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
    Name_to_handle_at,
    Open_by_handle_at,
    Close,
    Dup,
    Read,
    Creat,
    Mknod,
    Mknodat,
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

  /// This is the file inode; it is only used for name_to_handle_at
  /// and open_by_handle_at syscalls
  std::uint64_t file_inode;

  /// Path passed to the syscall; note that this is not valid
  /// for open_by_handle_at syscalls. You have to match the
  /// inode field with the name_to_handle_at system call
  std::string path;
};

/// Syscall event pretty printer, used for the --audit_fim_debug flag
std::ostream& operator<<(std::ostream& stream,
                         const SyscallEvent& syscall_event);

struct AuditdFimSubscriptionContext final : public SubscriptionContext {
 private:
  friend class AuditdFimEventPublisher;
};

struct AuditdFimEventContext final : public EventContext {
  std::vector<SyscallEvent> syscall_events;
};

using AuditdFimEventContextRef = std::shared_ptr<AuditdFimEventContext>;
using AuditdFimSubscriptionContextRef =
    std::shared_ptr<AuditdFimSubscriptionContext>;

/// This type maps audit event id with the corresponding syscall event object
using SyscallTraceContext = std::map<std::string, SyscallEvent>;

class AuditdFimEventPublisher final
    : public EventPublisher<AuditdFimSubscriptionContext,
                            AuditdFimEventContext> {
  DECLARE_PUBLISHER("auditfim");

 public:
  Status setUp() override;
  void configure() override;
  void tearDown() override;
  Status run() override;

  virtual ~AuditdFimEventPublisher() {
    tearDown();
  }

  /// Aggregates raw event records into syscall events
  static void ProcessEvents(AuditdFimEventContextRef event_context,
                            const std::vector<AuditEventRecord>& record_list,
                            SyscallTraceContext& trace_context) noexcept;

 private:
  /// Audit netlink subscription handle
  NetlinkSubscriptionHandle audit_netlink_subscription_;

  /// This is where audit records are assembled
  SyscallTraceContext syscall_trace_context_;
};
}
