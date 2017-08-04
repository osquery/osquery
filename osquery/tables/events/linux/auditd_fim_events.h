#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/events.h>

#include "osquery/events/linux/auditdfim.h"

namespace osquery {
/// This structure stores the information for a tracked file handle
struct AuditdFimHandleInformation final {
  /// Operation type affecting this file handle
  enum class OperationType { Open, Read, Write };

  /// The last operation executed on this file handle; this is used by the
  /// filtering logic to reduce output
  OperationType last_operation{OperationType::Open};

  /// The path for this file handle
  std::string path;
};

/// This structure contains a complex (i.e. not normalized) path. It is
/// mainly used to solve name_to_handle_at/open_by_handle_at syscalls.
struct AuditdFimPathInformation final {
  std::string path;
  std::string cwd;
};

/// This map contains the file inode emitted by the name_to_handle_at
/// system call. It is used to solve the file path of the
/// open_by_handle_at syscall.
using AuditdFimFileInodeMap =
    std::unordered_map<std::uint64_t, AuditdFimPathInformation>;

/// Holds the file descriptor map for a process
using AuditdFimHandleMap = std::unordered_map<int, AuditdFimHandleInformation>;

/// Contains the state of a tracked process
struct AuditdFimProcessState final {
  /// Contains the handle map for the process
  AuditdFimHandleMap handle_map;

  /// Contains the mapping for the file inodes emitted by
  /// name_to_handle_at syscalls, and it is used to retrieve
  /// the path for the open_by_handle_at system call.
  AuditdFimFileInodeMap inode_map;
};

/// Holds the process state for all encountered process ids
using AuditdFimProcessMap = std::unordered_map<__pid_t, AuditdFimProcessState>;

/// A simple vector of strings
using StringList = std::vector<std::string>;

/// Contains the AuditdFim configuration
struct AuditdFimConfiguration final {
  /// The paths included in the audit fim events
  StringList included_path_list;

  /// The paths excluded from the audit fim events. Takes precedence over
  /// included_path_list
  StringList excluded_path_list;

  /// Whether to only show writes or also open() and read() events
  bool show_accesses{true};
};

/// This subscriber receives syscall events from the publisher and
/// builds a file descriptor map for each process. Once a read or
/// write operation is performed, a new row is emitted (according
/// to how it has been configured).
class AuditdFimEventSubscriber final
    : public EventSubscriber<AuditdFimEventPublisher> {
  AuditdFimProcessMap process_map_;
  AuditdFimConfiguration configuration_;

 public:
  Status setUp() override;
  Status init() override;

  /// Applies the user configuration to the subscriber
  void configure() override;

  /// This callback is called once for each AuditdFimEventPublisher::fire()
  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);

  /// Processes the given events, updating the tracing context and emitting rows
  static Status ProcessEvents(
      std::vector<Row>& emitted_row_list,
      AuditdFimProcessMap& process_map,
      const AuditdFimConfiguration& configuration,
      const std::vector<SyscallEvent>& syscall_event_list) noexcept;

 private:
  /// Returns the process state for the specified pid
  static AuditdFimProcessMap::iterator GetOrCreateProcessState(
      AuditdFimProcessMap& process_map,
      __pid_t process_id,
      bool create_if_missing) noexcept;

  /// Drops the specified state from the map
  static void DropProcessState(AuditdFimProcessMap& process_map,
                               __pid_t process_id) noexcept;

  /// Updates the inode map (used for name_to_handle_at and open_by_handle_at)
  static void SaveInodeInformation(AuditdFimProcessMap& process_map,
                                   __pid_t process_id,
                                   __ino_t inode,
                                   const std::string& cwd,
                                   const std::string& path) noexcept;

  /// Returns the specified inode from the process state (used for
  /// name_to_handle_at and open_by_handle_at)
  static bool GetInodeInformation(
      AuditdFimProcessMap& process_map,
      __pid_t process_id,
      __ino_t inode,
      AuditdFimPathInformation& path_information) noexcept;

  /// Updates the specified handle in the process state
  static void SaveHandleInformation(
      AuditdFimProcessMap& process_map,
      __pid_t process_id,
      std::uint64_t fd,
      const std::string& path,
      AuditdFimHandleInformation::OperationType last_operation) noexcept;

  /// Returns information about the specified handle
  static bool GetHandleInformation(
      AuditdFimProcessMap& process_map,
      __pid_t process_id,
      std::uint64_t fd,
      AuditdFimHandleInformation& handle_info) noexcept;

  /// Removes the specified file descriptor from the process state
  static void DropHandleInformation(AuditdFimProcessMap& process_map,
                                    __pid_t process_id,
                                    std::uint64_t fd) noexcept;
};
}
