#pragma once

#include <sys/types.h>


#include <string>
#include <unordered_map>
#include <vector>


#include <boost/variant.hpp>


#include <osquery/events.h>


#include "osquery/events/linux/syscall_monitor.h"

namespace osquery {
struct AuditdFimInodeDescriptor final {
  enum class Type {
    File,
    Folder
  };

  Type type;
  std::string path;
};

struct AuditdFimFdDescriptor final {
  enum class OperationType { Open, Read, Write };

  ino_t inode;
  OperationType last_operation;
};

using AuditdFimInodeMap = std::unordered_map<ino_t, AuditdFimInodeDescriptor>;
using AuditdFimFdMap = std::unordered_map<int, AuditdFimFdDescriptor>;
using AuditdFimProcessMap = std::unordered_map<pid_t, AuditdFimFdMap>;

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

struct AuditdFimContext final {
  AuditdFimConfiguration configuration;
  AuditdFimProcessMap process_map;
  AuditdFimInodeMap inode_map;
};

struct AuditdFimSyscallRecord final {
  enum class Type {
    Link,
    Symlink,
    Unlink,
    Rename,
    Open,
    Close,
    Dup,
    Read,
    Write,
    Mmap
  };

  Type type;
  bool partial;

  pid_t process_id;
  pid_t parent_process_id;
  std::string executable_path;
  std::uint64_t return_value;
};

struct AuditdFimPathRecordItem final {
  std::size_t index;
  ino_t inode;
  std::string path;
};

struct AuditdFimRenameData final {
  std::string source;
  std::string destination;
};

struct AuditdFimIOData final {
  enum class Type {
    Open,
    Read,
    Write,
    Close,
    Unlink
  };

  std::string target;
  Type type;
  bool state_changed;
};

using SyscallData = boost::variant<AuditdFimRenameData, AuditdFimIOData>;

struct AuditdFimSyscallContext final {
  enum class Type {
    Link,
    Symlink,
    Unlink,
    Rename,
    Open,
    Close,
    Dup,
    Read,
    Write,
    Mmap,
    NameToHandleAt
  };

  Type type;
  std::uint64_t syscall_number;
  bool partial;

  std::string cwd;
  std::unordered_map<std::size_t, AuditdFimPathRecordItem> path_record_map;

  pid_t process_id;
  pid_t parent_process_id;
  std::string executable_path;
  std::uint64_t return_value;

  SyscallData syscall_data;
};

/// This subscriber receives syscall events from the publisher and
/// builds a file descriptor map for each process. Once a read or
/// write operation is performed, a new row is emitted (according
/// to how it has been configured).
class AuditdFimEventSubscriber final
    : public EventSubscriber<AuditEventPublisher> {
 public:
  Status setUp() override;
  Status init() override;

  /// Applies the user configuration to the subscriber
  void configure() override;

  /// This callback is called once for each AuditdFimEventPublisher::fire()
  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);

  /// Processes the given events, updating the tracing context
  static Status ProcessEvents(
      std::vector<Row> &emitted_row_list,
      AuditdFimContext &fim_context,
      const std::vector<AuditEvent>& event_list) noexcept;

private:
  AuditdFimContext context_;
};
}
