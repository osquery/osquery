/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/linux/auditdfim.h"
#include "osquery/core/conversions.h"

#include <boost/filesystem.hpp>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <asm/unistd_64.h>

#include <iostream>

namespace osquery {
HIDDEN_FLAG(bool, audit_fim_debug, false, "Show audit FIM events");
DECLARE_bool(audit_allow_fim_events);

REGISTER(AuditdFimEventPublisher, "event_publisher", "auditfim");

namespace {
SyscallEvent::Type GetSyscallEventType(int syscall_number) noexcept {
  switch (syscall_number) {
  case __NR_execve:
    return SyscallEvent::Type::Execve;

  case __NR_exit:
    return SyscallEvent::Type::Exit;

  case __NR_exit_group:
    return SyscallEvent::Type::Exit_group;

  case __NR_open:
    return SyscallEvent::Type::Open;

  case __NR_openat:
    return SyscallEvent::Type::Openat;

  case __NR_name_to_handle_at:
    return SyscallEvent::Type::Name_to_handle_at;

  case __NR_open_by_handle_at:
    return SyscallEvent::Type::Open_by_handle_at;

  case __NR_close:
    return SyscallEvent::Type::Close;

  case __NR_dup:
  case __NR_dup2:
  case __NR_dup3:
    return SyscallEvent::Type::Dup;

  case __NR_mmap:
    return SyscallEvent::Type::Mmap;

  case __NR_write:
    return SyscallEvent::Type::Write;

  case __NR_read:
    return SyscallEvent::Type::Read;

  case __NR_creat:
    return SyscallEvent::Type::Creat;

  case __NR_mknod:
    return SyscallEvent::Type::Mknod;

  case __NR_mknodat:
    return SyscallEvent::Type::Mknodat;

  default:
    return SyscallEvent::Type::Invalid;
  }
}

/// Returns the specified field name from the given audit event record; if
/// the field is missing, the user-supplied default value is returned
/// instead
bool GetAuditRecordField(
    std::string& value,
    const AuditEventRecord& record,
    const std::string& field_name,
    const std::string& default_value = std::string()) noexcept {
  const auto& field_map = record.fields;

  auto field_it = field_map.find(field_name);
  if (field_it == field_map.end()) {
    value = default_value;
    return false;
  }

  value = field_it->second;
  return true;
}

/// Returns the specified field name from the given audit event record,
/// converting it to an unsigned integer; if the field is
/// missing, the user-supplied default value is returned instead
bool GetAuditRecordField(std::uint64_t& value,
                         const AuditEventRecord& record,
                         const std::string& field_name,
                         std::size_t base = 10,
                         std::uint64_t default_value = 0) noexcept {
  std::string string_value;
  if (!GetAuditRecordField(string_value, record, field_name, "")) {
    value = default_value;
    return false;
  }

  long long temp;
  if (!safeStrtoll(string_value, base, temp)) {
    value = default_value;
    return false;
  }

  value = static_cast<std::uint64_t>(temp);
  return true;
}

bool ParseAuditSyscallRecord(
    SyscallEvent& syscall_event,
    const AuditEventRecord& audit_event_record) noexcept {
  syscall_event = {};

  // Contains the list of syscalls that we need to track
  const std::vector<std::uint64_t> syscall_filter = {__NR_execve,
                                                     __NR_exit,
                                                     __NR_exit_group,
                                                     __NR_open,
                                                     __NR_openat,
                                                     __NR_name_to_handle_at,
                                                     __NR_open_by_handle_at,
                                                     __NR_close,
                                                     __NR_dup,
                                                     __NR_dup2,
                                                     __NR_dup3,
                                                     __NR_write,
                                                     __NR_read,
                                                     __NR_mmap,
                                                     __NR_creat,
                                                     __NR_mknodat,
                                                     __NR_mknod};

  // Contains the list of syscalls that accept a file descriptor
  // Note that the mmap file descriptor is inside the AUDIT_MMAP event record
  const std::vector<std::uint64_t> input_fd_syscall_list = {
      __NR_dup, __NR_dup2, __NR_dup3, __NR_close, __NR_write, __NR_read};

  // Contains the list of syscalls that outputs a file descriptor
  const std::vector<std::uint64_t> output_fd_syscall_list = {
      __NR_open,
      __NR_openat,
      __NR_open_by_handle_at,
      __NR_dup,
      __NR_dup2,
      __NR_dup3,
      __NR_creat,
      __NR_mknodat,
      __NR_mknod};

  // Searches the specified vector for the given syscall number; it used with
  // the previously-defined vectors to detect what values the syscall accepts
  // and/or outputs
  auto L_ContainsSyscall = [](const std::vector<std::uint64_t>& filter,
                              std::uint64_t syscall) -> bool {
    return (std::find(filter.begin(), filter.end(), syscall) != filter.end());
  };

  // Attempt to get the syscall number; we can't go on without it!
  std::uint64_t syscall_number;
  if (!GetAuditRecordField(syscall_number, audit_event_record, "syscall")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The syscall field "
               "is either missing or not valid.";

    return false;
  }

  if (!L_ContainsSyscall(syscall_filter, syscall_number))
    return false;

  syscall_event.partial = false;
  syscall_event.type = GetSyscallEventType(syscall_number);

  //
  // Special syscall handling
  //

  // mmap syscalls
  // the third parameter (field a2) contains the requested
  // memory protection
  if (syscall_number == __NR_mmap) {
    std::uint64_t memory_protection_flags;
    if (!GetAuditRecordField(
            memory_protection_flags, audit_event_record, "a2", 16)) {
      VLOG(1) << "Malformed AUDIT_SYSCALL record received. The memory "
                 "protection flags are either missing or not valid.";

      // we can't determine if this is a write or not; assume the worst case
      syscall_event.mmap_memory_protection_flags = PROT_READ | PROT_WRITE;

    } else {
      syscall_event.mmap_memory_protection_flags =
          static_cast<int>(memory_protection_flags);
    }
  }

  //
  // Common handling for the remaining syscalls
  //

  // Note that mmap is handled differently; the file descriptor is inside
  // the AUDIT_MMAP record
  if (L_ContainsSyscall(input_fd_syscall_list, syscall_number)) {
    std::uint64_t input_fd;
    if (!GetAuditRecordField(input_fd, audit_event_record, "a0", 16)) {
      VLOG(1) << "Malformed AUDIT_SYSCALL record received. The file "
                 "descriptor is either missing or not valid.";

      syscall_event.input_fd = -1;
      syscall_event.partial = true;

    } else {
      syscall_event.input_fd = static_cast<int>(input_fd);
    }
  }

  // This is the value that the syscall has returned
  if (L_ContainsSyscall(output_fd_syscall_list, syscall_number)) {
    std::uint64_t output_fd;
    if (!GetAuditRecordField(output_fd, audit_event_record, "exit")) {
      VLOG(1) << "Malformed AUDIT_SYSCALL record received. The exit field "
                 "is either missing or not valid.";

      syscall_event.output_fd = -1;
      syscall_event.partial = true;

    } else {
      syscall_event.output_fd = static_cast<int>(output_fd);
    }
  }

  // Not all syscalls have a 'success' field; in case it is missing, it's
  // implicitly a 'yes'
  GetAuditRecordField(
      syscall_event.success, audit_event_record, "success", "yes");

  if (!GetAuditRecordField(
          syscall_event.executable_path, audit_event_record, "exe")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The exe field is "
               "missing.";

    syscall_event.partial = true;
  }

  // Parent process id
  std::uint64_t parent_process_id;
  if (!GetAuditRecordField(parent_process_id, audit_event_record, "ppid")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
               "process id field is either missing or not valid.";

    syscall_event.parent_process_id = 0;
    syscall_event.partial = true;

  } else {
    syscall_event.parent_process_id = static_cast<__pid_t>(parent_process_id);
  }

  // Process id
  std::uint64_t process_id;
  if (!GetAuditRecordField(process_id, audit_event_record, "pid")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The process id "
               "field is either missing or not valid.";

    return false;

  } else {
    syscall_event.process_id = static_cast<__pid_t>(parent_process_id);
  }

  return true;
}
}

Status AuditdFimEventPublisher::setUp() {
  if (!FLAGS_audit_allow_fim_events) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void AuditdFimEventPublisher::configure() {
  // Only subscribe if we are actually going to have listeners
  if (audit_netlink_subscription_ == 0) {
    audit_netlink_subscription_ = AuditdNetlink::getInstance().subscribe();
  }
}

void AuditdFimEventPublisher::tearDown() {
  if (audit_netlink_subscription_ != 0) {
    AuditdNetlink::getInstance().unsubscribe(audit_netlink_subscription_);
    audit_netlink_subscription_ = 0;
  }
}

Status AuditdFimEventPublisher::run() {
  // Request our event queue from the AuditdNetlink component
  auto audit_event_record_queue =
      AuditdNetlink::getInstance().getEvents(audit_netlink_subscription_);

  auto event_context = createEventContext();
  ProcessEvents(
      event_context, audit_event_record_queue, syscall_trace_context_);

  if (!event_context->syscall_events.empty()) {
    fire(event_context);
  }

  return Status(0, "OK");
}

void AuditdFimEventPublisher::ProcessEvents(
    AuditdFimEventContextRef event_context,
    const std::vector<AuditEventRecord>& record_list,
    SyscallTraceContext& trace_context) noexcept {
  // Assemble each record into a SyscallEvent object; an event is
  // complete when we receive the terminator (AUDIT_EOE)
  for (const auto& audit_event_record : record_list) {
    auto audit_event_it = trace_context.find(audit_event_record.audit_id);

    if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      SyscallEvent syscall_event;
      if (ParseAuditSyscallRecord(syscall_event, audit_event_record)) {
        trace_context[audit_event_record.audit_id] = syscall_event;
      }

      // Contains the working directory; it is always followed by an
      // AUDIT_PATH record, and it's useful in case the specified path
      // is relative
    } else if (audit_event_record.type == AUDIT_CWD) {
      if (audit_event_it == trace_context.end()) {
        VLOG(1) << "Received an orphaned AUDIT_CWD record. Skipping it...";
        continue;
      }

      auto& syscall_event = audit_event_it->second;
      if (!GetAuditRecordField(syscall_event.cwd, audit_event_record, "cwd")) {
        VLOG(1) << "Malformed AUDIT_CWD record received. The cwd field is "
                   "missing.";

        syscall_event.partial = true;
      }

      // This record contains additional parameters for the mmap() syscalls; we
      // are only interested in the file descriptor
    } else if (audit_event_record.type == AUDIT_MMAP) {
      if (audit_event_it == trace_context.end()) {
        VLOG(1) << "Received an orphaned AUDIT_MMAP record. Skipping it...";
        continue;
      }

      auto& syscall_event = audit_event_it->second;

      std::uint64_t input_fd;
      if (!GetAuditRecordField(input_fd, audit_event_record, "fd")) {
        VLOG(1) << "Malformed AUDIT_MMAP record received. The fd field is "
                   "missing.";

        syscall_event.partial = true;
      } else {
        syscall_event.input_fd = static_cast<int>(input_fd);
      }

      // This record is emitted once for each path passed to the syscall. For
      // example, the execve uses two records of this type
    } else if (audit_event_record.type == AUDIT_PATH) {
      if (audit_event_it == trace_context.end()) {
        VLOG(1) << "Received an orphaned AUDIT_PATH record. Skipping it...";
        continue;
      }

      // The mknod/mknodat/creat syscalls emit two AUDIT_PATH records; the
      // first one is the working directory, while the second one is
      // the actual file path
      auto& syscall_event = audit_event_it->second;
      if (syscall_event.type == SyscallEvent::Type::Mknod ||
          syscall_event.type == SyscallEvent::Type::Mknodat ||
          syscall_event.type == SyscallEvent::Type::Creat) {
        std::uint64_t item_id;
        if (!GetAuditRecordField(item_id, audit_event_record, "item", 10, 0)) {
          VLOG(1) << "Malformed AUDIT_PATH record received. The item field is "
                     "missing.";
        }

        if (item_id != 1) {
          continue;
        }
      }

      if (!GetAuditRecordField(
              syscall_event.path, audit_event_record, "name", "")) {
        VLOG(1) << "Malformed AUDIT_PATH record received. The path field is "
                   "missing.";

        syscall_event.partial = true;
      }

      // We also need the inode number for these two syscalls, because it's the
      // only piece of data that links those two operations
      if (syscall_event.type == SyscallEvent::Type::Name_to_handle_at ||
          syscall_event.type == SyscallEvent::Type::Open_by_handle_at) {
        if (!GetAuditRecordField(
                syscall_event.file_inode, audit_event_record, "inode", 16)) {
          VLOG(1) << "Malformed AUDIT_SYSCALL record received. The file "
                     "inode is either missing or invalid.";

          syscall_event.partial = true;

        } else {
          syscall_event.file_inode = 0;
        }
      }

      // This is the event terminator, and it's always sent for AUDIT_SYSCALL
      // events.
    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == trace_context.end()) {
        VLOG(1) << "Received an orphaned AUDIT_EOE record. Skipping it...";
        continue;
      }

      auto completed_syscall_event = audit_event_it->second;
      trace_context.erase(audit_event_it);

      if (FLAGS_audit_fim_debug) {
        std::cout << completed_syscall_event << std::endl;
      }

      if (completed_syscall_event.process_id != getpid()) {
        event_context->syscall_events.push_back(completed_syscall_event);
      }
    }
  }

  // Drop events that are older than 5 minutes; it means that we have failed to
  // receive the end of record and will never complete them correctly

  std::time_t current_time;
  std::time(&current_time);

  std::unordered_map<std::string, std::time_t> timestamp_cache;

  // The first part of the audit id is a timestamp: 1501323932.710:7670542
  for (auto syscall_it = trace_context.begin();
       syscall_it != trace_context.end();) {
    const auto& audit_event_id = syscall_it->first;
    std::time_t event_timestamp;

    auto timestamp_it = timestamp_cache.find(audit_event_id);
    if (timestamp_it == timestamp_cache.end()) {
      std::string string_timestamp = audit_event_id.substr(0, 10);

      long long int converted_value;
      if (!safeStrtoll(string_timestamp, 10, converted_value)) {
        event_timestamp = 0;
      } else {
        event_timestamp = static_cast<std::time_t>(converted_value);
      }

      timestamp_cache[audit_event_id] = event_timestamp;

    } else {
      event_timestamp = timestamp_it->second;
    }

    if (current_time - event_timestamp >= 300) {
      syscall_it = trace_context.erase(syscall_it);
    } else {
      syscall_it++;
    }
  }
}

std::ostream& operator<<(std::ostream& stream,
                         const SyscallEvent& syscall_event) {
  stream << "ppid: " << syscall_event.parent_process_id << " ";
  stream << "pid: " << syscall_event.process_id << " ";

  bool show_path_and_cwd = false;
  bool show_input_file_descriptor = false;
  bool show_output_file_descriptor = false;
  bool show_memory_protection = false;

  switch (syscall_event.type) {
  case SyscallEvent::Type::Execve: {
    stream << "execve";
    show_path_and_cwd = true;
    break;
  }

  case SyscallEvent::Type::Exit: {
    stream << "exit";
    break;
  }

  case SyscallEvent::Type::Exit_group: {
    stream << "exit_group";
    break;
  }

  case SyscallEvent::Type::Open: {
    stream << "open";

    show_path_and_cwd = true;
    show_output_file_descriptor = true;

    break;
  }

  case SyscallEvent::Type::Openat: {
    stream << "openat";

    show_path_and_cwd = true;
    show_output_file_descriptor = true;

    break;
  }

  case SyscallEvent::Type::Open_by_handle_at: {
    stream << "open_by_handle_at";

    show_input_file_descriptor = true;
    show_output_file_descriptor = true;

    break;
  }

  case SyscallEvent::Type::Close: {
    stream << "close";
    show_input_file_descriptor = true;
    break;
  }

  case SyscallEvent::Type::Dup: {
    stream << "dup";
    show_input_file_descriptor = true;
    show_output_file_descriptor = true;
    break;
  }

  case SyscallEvent::Type::Read: {
    stream << "read";
    show_input_file_descriptor = true;
    break;
  }

  case SyscallEvent::Type::Write: {
    stream << "write";
    show_input_file_descriptor = true;
    break;
  }

  case SyscallEvent::Type::Mmap: {
    stream << "mmap";
    show_input_file_descriptor = true;
    show_memory_protection = true;
    break;
  }

  default: {
    stream << "invalid_syscall_id";
    break;
  }
  }

  stream << "(";

  if (show_path_and_cwd) {
    stream << "cwd:" << syscall_event.cwd << ", ";
    stream << "path:" << syscall_event.path;
  } else if (show_input_file_descriptor) {
    stream << "input_fd:" << syscall_event.input_fd;

    if (show_memory_protection) {
      stream << ", memory_protection:0x" << std::hex
             << syscall_event.mmap_memory_protection_flags;
    }
  }

  stream << ")";
  if (show_output_file_descriptor)
    stream << " -> " << syscall_event.output_fd;

  return stream;
}
}
