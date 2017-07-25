/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/linux/auditfim.h"
#include "osquery/core/conversions.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem.hpp>
#include <boost/utility/string_ref.hpp>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <asm/unistd_64.h>

#include <iostream>

namespace osquery {
HIDDEN_FLAG(bool, audit_fim_debug, false, "Show audit FIM events");
DECLARE_bool(audit_allow_file_events);

REGISTER(AuditFimEventPublisher, "event_publisher", "auditfim");

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

  default:
    return SyscallEvent::Type::Invalid;
  }
}

/// Returns the specified field name from the given audit event record; if the
/// field is
/// missing, the user-supplied default value is returned instead
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

  // Contains the list of syscall that we need to track
  const std::vector<std::uint64_t> syscall_filter = {__NR_execve,
                                                     __NR_exit,
                                                     __NR_exit_group,
                                                     __NR_open,
                                                     __NR_openat,
                                                     __NR_open_by_handle_at,
                                                     __NR_close,
                                                     __NR_dup,
                                                     __NR_dup2,
                                                     __NR_dup3,
                                                     __NR_write,
                                                     __NR_read,
                                                     __NR_mmap};

  // Contains the list of syscalls that accept a file descriptor
  // Note that the mmap file descriptor is inside the AUDIT_MMAP event record
  const std::vector<std::uint64_t> input_fd_syscall_list = {
      __NR_dup, __NR_dup2, __NR_dup3, __NR_close, __NR_write, __NR_read};

  // Contains the lits of syscalls that outputs a file descriptor
  const std::vector<std::uint64_t> output_fd_syscall_list = {
      __NR_open,
      __NR_openat,
      __NR_open_by_handle_at,
      __NR_dup,
      __NR_dup2,
      __NR_dup3};

  // Searches the specified vector for the given syscall number; it used with
  // the
  // previously-defined vectors to detect what values the syscall accepts and/or
  // outputs
  auto L_ContainsSyscall = [](const std::vector<std::uint64_t>& filter,
                              std::uint64_t syscall) -> bool {
    return (std::find(filter.begin(), filter.end(), syscall) != filter.end());
  };

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

  // Special handling for mmap syscalls; the third parameter (a2 field)
  // contains the requested
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

  GetAuditRecordField(
      syscall_event.success, audit_event_record, "success", "yes");

  if (!GetAuditRecordField(
          syscall_event.executable_path, audit_event_record, "exe")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The exe field is "
               "missing.";

    syscall_event.partial = true;
  }

  std::uint64_t parent_process_id;
  if (!GetAuditRecordField(parent_process_id, audit_event_record, "ppid")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
               "process id field is either missing or not valid.";

    syscall_event.parent_process_id = 0;
    syscall_event.partial = true;

  } else {
    syscall_event.parent_process_id = static_cast<__pid_t>(parent_process_id);
  }

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

Status AuditFimEventPublisher::setUp() {
  if (!FLAGS_audit_allow_file_events) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void AuditFimEventPublisher::configure() {
  // Only subscribe if we are actually going to have listeners
  if (audit_netlink_subscription_ == 0) {
    audit_netlink_subscription_ = AuditNetlink::getInstance().subscribe();
  }
}

void AuditFimEventPublisher::tearDown() {
  if (audit_netlink_subscription_ != 0) {
    AuditNetlink::getInstance().unsubscribe(audit_netlink_subscription_);
    audit_netlink_subscription_ = 0;
  }
}

Status AuditFimEventPublisher::run() {
  // Request our event queue from the AuditNetlink component
  auto audit_event_record_queue =
      AuditNetlink::getInstance().getEvents(audit_netlink_subscription_);

  auto event_context = createEventContext();

  // Build a SyscallEvent object for each audit event
  for (const auto& audit_event_record : audit_event_record_queue) {
    auto audit_event_it = syscall_event_list_.find(audit_event_record.audit_id);

    if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != syscall_event_list_.end()) {
        VLOG(1) << "Received a duplicated event.";
        syscall_event_list_.erase(audit_event_it);
      }

      SyscallEvent syscall_event;
      if (ParseAuditSyscallRecord(syscall_event, audit_event_record)) {
        syscall_event_list_[audit_event_record.audit_id] = syscall_event;
      }

    } else if (audit_event_record.type == AUDIT_CWD) {
      if (audit_event_it == syscall_event_list_.end()) {
        VLOG(1) << "Received an orphaned AUDIT_CWD record. Skipping it...";
        continue;
      }

      auto& syscall_event = audit_event_it->second;
      if (!GetAuditRecordField(syscall_event.cwd, audit_event_record, "cwd")) {
        VLOG(1) << "Malformed AUDIT_CWD record received. The cwd field is "
                   "missing.";

        syscall_event.partial = true;
      }

    } else if (audit_event_record.type == AUDIT_MMAP) {
      if (audit_event_it == syscall_event_list_.end()) {
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

    } else if (audit_event_record.type == AUDIT_PATH) {
      if (audit_event_it == syscall_event_list_.end()) {
        VLOG(1) << "Received an orphaned AUDIT_PATH record. Skipping it...";
        continue;
      }

      auto& syscall_event = audit_event_it->second;
      if (!GetAuditRecordField(
              syscall_event.path, audit_event_record, "name", "")) {
        VLOG(1) << "Malformed AUDIT_PATH record received. The path field is "
                   "missing.";

        syscall_event.partial = true;
      }

    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == syscall_event_list_.end()) {
        VLOG(1) << "Received an orphaned AUDIT_EOE record. Skipping it...";
        continue;
      }

      auto completed_syscall_event = audit_event_it->second;
      syscall_event_list_.erase(audit_event_it);

      if (FLAGS_audit_fim_debug) {
        std::cout << completed_syscall_event << std::endl;
      }

      if (completed_syscall_event.process_id != getpid()) {
        event_context->syscall_events.push_back(completed_syscall_event);
      }
    }
  }

  if (!event_context->syscall_events.empty()) {
    fire(event_context);
  }

  return Status(0, "OK");
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
