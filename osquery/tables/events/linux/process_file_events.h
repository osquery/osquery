/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <sys/types.h>

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/variant.hpp>

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/auditeventpublisher.h>

namespace osquery {
/// An inode descriptor, containing the file (or folder) path
struct AuditdFimInodeDescriptor final {
  enum class Type { File, Folder };

  Type type;
  std::string path;
};

/// An fd descriptor, containing the inode used to solve the path
struct AuditdFimFdDescriptor final {
  enum class OperationType { Open, OpenTruncate, Read, Write };

  ino_t inode;
  OperationType last_operation;
};

/// A global inode map
class AuditdFimInodeMap final {
 public:
  AuditdFimInodeMap();

  /// Returns a reference to the specified inode object
  bool getReference(AuditdFimInodeDescriptor*& ino_desc, ino_t inode);

  /// Removes and returns the specified inode object
  bool takeAndRemove(AuditdFimInodeDescriptor& ino_desc, ino_t inode);

  /// Saves a new inode into the map
  void save(ino_t inode,
            AuditdFimInodeDescriptor::Type type,
            const std::string& path);

  /// Removes the specified inode
  void remove(ino_t inode);

  /// Removes all inodes from the map
  void clear();

 private:
  /// The global inode map
  std::map<ino_t, AuditdFimInodeDescriptor> data_;
};

/// Contains
class AuditdFimFdMap final {
 public:
  AuditdFimFdMap(pid_t process_id);

  /// Sets the new process id that owns this fd map
  void setProcessId(pid_t process_id);

  /// Returns a reference to the specified fd object
  bool getReference(AuditdFimFdDescriptor*& fd_desc, std::uint64_t fd);

  /// Duplicates the specified fd (used for dup/dup2/dup3)
  bool duplicate(std::uint64_t fd, std::uint64_t new_fd);

  /// Removes and returns the specified fd object
  bool takeAndRemove(AuditdFimFdDescriptor& fd_desc, std::uint64_t fd);

  /// Saves a new fd in the map
  void save(std::uint64_t fd,
            ino_t inode,
            AuditdFimFdDescriptor::OperationType last_operation =
                AuditdFimFdDescriptor::OperationType::Open);

  /// Removes all items from the map
  void clear();

 private:
  /// Prints a warning when an untracked fd is found
  void printUntrackedFdWarning(std::uint64_t fd);

 private:
  /// The process id that owns this fd map
  pid_t process_id_;

  /// A time-based filter to avoid spamming the warning log
  std::time_t warning_suppression_timer_{0};

  /// A map of all the known file descriptors for this process
  std::unordered_map<std::uint64_t, AuditdFimFdDescriptor> data_;
};

/// A utility class to track processes and their fd maps
class AuditdFimProcessMap final {
 public:
  /// Returns a reference to the specified fd object
  bool getReference(AuditdFimFdDescriptor*& fd_desc,
                    pid_t process_id,
                    std::uint64_t fd);

  /// Creates a new empty process
  void create(pid_t process_id);

  /// Duplicates the specified fd. Used for dup/dup2/dup3
  bool duplicate(pid_t process_id, std::uint64_t fd, std::uint64_t new_fd);

  /// Clones the specified process (used for fork/vfork/clone)
  bool clone(pid_t old_pid, pid_t new_pid);

  /// Removes and returns the specified fd object
  bool takeAndRemove(AuditdFimFdDescriptor& fd_desc,
                     pid_t process_id,
                     std::uint64_t fd);

  /// Saves a new fd in the specified process map
  void save(std::uint64_t fd,
            pid_t process_id,
            ino_t inode,
            AuditdFimFdDescriptor::OperationType last_operation =
                AuditdFimFdDescriptor::OperationType::Open);

  /// Removes all items
  void clear();

 private:
  /// Prints a warning (VLOG) when an untracked pid is found
  void printUntrackedPidWarning(pid_t pid);

 private:
  /// Time-based filtering to avoid spamming the warning log
  std::map<pid_t, std::time_t> warning_suppression_filter_;

  /// An fd map for each process
  std::map<pid_t, AuditdFimFdMap> data_;
};

/// A simple vector of strings
using StringList = std::vector<std::string>;

/// The fim context contains configuration and process state
struct AuditdFimContext final {
  /// The paths included in the audit fim events
  StringList included_path_list;

  /// The process map, containing an fd map for each process
  AuditdFimProcessMap process_map;

  /// The global inode map
  AuditdFimInodeMap inode_map;
};

/// Used to aggregate each AUDIT_PATH record
struct AuditdFimPathRecordItem final {
  std::size_t index;
  ino_t inode;
  std::string path;
};

/// Contains information for syscalls with 2 paths (link, rename, etc)
struct AuditdFimSrcDestData final {
  std::string source;
  std::string destination;
};

/// Contains information for syscalls that create/write/read files
struct AuditdFimIOData final {
  enum class Type { Open, OpenTruncate, Read, Write, Close, Unlink };

  std::string target;
  Type type;
  bool state_changed;
};

using SyscallData = boost::variant<AuditdFimSrcDestData, AuditdFimIOData>;

/// Contains everything that is related to a specific syscall
struct AuditdFimSyscallContext final {
  enum class Type {
    Link,
    Symlink,
    Unlink,
    Rename,
    Open,
    OpenTruncate,
    Close,
    Dup,
    Read,
    Write,
    Truncate,
    Mmap,
    NameToHandleAt,
    CloneOrFork
  };

  /// Syscall type
  Type type;

  /// Syscall number
  std::uint64_t syscall_number;

  /// If true, one or more event components were missing
  bool partial;

  /// Working directory
  std::string cwd;

  // A collection of all the AUDIT_PATH records we found
  std::unordered_map<std::size_t, AuditdFimPathRecordItem> path_record_map;

  /// The process id
  pid_t process_id;

  /// The parent process id
  pid_t parent_process_id;

  /// The process uid
  uid_t process_uid;

  /// The process gid
  gid_t process_gid;

  /// The process auid
  uid_t process_auid;

  /// The process euid
  uid_t process_euid;

  /// The process egid
  gid_t process_egid;

  /// The process fsuid
  uid_t process_fsuid;

  /// The process fsgid
  gid_t process_fsgid;

  /// The process suid
  uid_t process_suid;

  /// The process sgid
  gid_t process_sgid;

  // Path of the executable that generated the event
  std::string executable_path;

  // This is the return value of the syscall; used with the system calls that
  // return a file descriptor.
  std::uint64_t return_value;

  // Syscall data
  SyscallData syscall_data;

  /// True if the AUDIT_MMAP record has been received
  bool mmap_record_present;

  /// This field is dedicated to mmap() and contains the file descriptor
  std::uint64_t mmap_file_descriptor;

  /// This field is dedicated to mmap() and contains the memory protection flags
  std::uint64_t mmap_prot_flags;
};

/// This subscriber receives syscall events from the publisher and
/// builds a file descriptor map for each process. Once a read or
/// write operation is performed, a new row is emitted (according
/// to how it has been configured).
class ProcessFileEventSubscriber final
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
      std::vector<Row>& emitted_row_list,
      AuditdFimContext& fim_context,
      const std::vector<AuditEvent>& event_list) noexcept;

  /// Returns the set of syscalls that this subscriber can handle
  static const std::set<int>& GetSyscallSet() noexcept;

 private:
  /// This structure holds information like handle and inode maps
  AuditdFimContext context_;
};
} // namespace osquery
