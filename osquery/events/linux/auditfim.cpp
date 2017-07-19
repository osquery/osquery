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
  const std::vector<int> syscall_filter = {__NR_execve,
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

  // The mmap file descriptor is inside the AUDIT_MMAP event record
  const std::vector<int> input_fd_syscall_list = {
      __NR_dup, __NR_dup2, __NR_dup3, __NR_close, __NR_write, __NR_read};

  const std::vector<int> output_fd_syscall_list = {__NR_open,
                                                   __NR_openat,
                                                   __NR_open_by_handle_at,
                                                   __NR_dup,
                                                   __NR_dup2,
                                                   __NR_dup3};

  auto L_ContainsSyscall = [](const std::vector<int>& filter,
                              int syscall) -> bool {
    return (std::find(filter.begin(), filter.end(), syscall) != filter.end());
  };

  auto L_GetFieldFromMap = [](
      const std::map<std::string, std::string>& field_map,
      const std::string& name,
      const std::string& default_value) -> std::string {
    auto field_it = field_map.find(name);
    if (field_it == field_map.end())
      return default_value;

    return field_it->second;
  };

  auto audit_event_record_queue =
      AuditNetlink::getInstance().getEvents(audit_netlink_subscription_);

  auto event_context = createEventContext();

  for (const auto& audit_event_record : audit_event_record_queue) {
    auto audit_event_it = syscall_event_list_.find(audit_event_record.audit_id);

    if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != syscall_event_list_.end()) {
        std::cout << "DUPLICATED!" << std::endl;
        syscall_event_list_.erase(audit_event_it);
      }

      std::string field_value =
          L_GetFieldFromMap(audit_event_record.fields, "syscall", "");

      long long int syscall_number;
      if (!safeStrtoll(field_value, 10, syscall_number)) {
        std::cout << "MALFORMED SYSCALL EVENT (invalid field)" << std::endl;
        continue;
      }

      if (!L_ContainsSyscall(syscall_filter, syscall_number))
        continue;

      SyscallEvent syscall_event;
      syscall_event.partial = false;

      syscall_event.type = GetSyscallEventType(syscall_number);

      // Special handling for mmap syscalls; the third parameter (a2 field)
      // contains the requested
      // memory protection
      if (syscall_number == __NR_mmap) {
        field_value = L_GetFieldFromMap(audit_event_record.fields, "a2", "");

        long long int memory_protection_flags;
        if (!safeStrtoll(field_value, 16, memory_protection_flags)) {
          std::cout << "MALFORMED SYSCALL EVENT (invalid a2 parameter for the "
                       "mmap() syscall)"
                    << std::endl;

          // we can't determine if this is a write or not; assume the worst case
          syscall_event.mmap_memory_protection_flags = PROT_READ | PROT_WRITE;
          syscall_event.partial = true;

        } else {
          syscall_event.mmap_memory_protection_flags =
              static_cast<int>(memory_protection_flags);
        }
      }

      // Note that mmap is handled differently; the file descriptor is inside
      // the AUDIT_MMAP record
      if (L_ContainsSyscall(input_fd_syscall_list, syscall_number)) {
        field_value = L_GetFieldFromMap(audit_event_record.fields, "a0", "");

        long long int input_fd;
        if (!safeStrtoll(field_value, 16, input_fd)) {
          std::cout << "MALFORMED SYSCALL EVENT (invalid close() parameter)"
                    << std::endl;
          syscall_event.input_fd = -1;
          syscall_event.partial = true;

        } else {
          syscall_event.input_fd = static_cast<int>(input_fd);
        }
      }

      if (L_ContainsSyscall(output_fd_syscall_list, syscall_number)) {
        field_value = L_GetFieldFromMap(audit_event_record.fields, "exit", "");

        long long int output_fd;
        if (!safeStrtoll(field_value, 10, output_fd)) {
          std::cout << "MALFORMED SYSCALL EVENT (invalid exit field)"
                    << std::endl;
          syscall_event.output_fd = -1;
          syscall_event.partial = true;

        } else {
          syscall_event.output_fd = static_cast<int>(output_fd);
        }
      }

      syscall_event.success =
          L_GetFieldFromMap(audit_event_record.fields, "success", "yes");

      field_value = L_GetFieldFromMap(audit_event_record.fields, "exe", "");
      if (field_value.empty()) {
        syscall_event.partial = true;
        std::cout << "MISSING EXE FROM SYSCALL" << std::endl;
      }
      syscall_event.executable_path = field_value;

      field_value = L_GetFieldFromMap(audit_event_record.fields, "ppid", "");

      long long int process_id_value;
      if (!safeStrtoll(field_value, 10, process_id_value)) {
        std::cout << "MALFORMED SYSCALL EVENT (invalid ppid field)"
                  << std::endl;
        syscall_event.partial = true;
        continue;
      }

      syscall_event.parent_process_id = static_cast<__pid_t>(process_id_value);

      field_value = L_GetFieldFromMap(audit_event_record.fields, "pid", "");
      if (!safeStrtoll(field_value, 10, process_id_value)) {
        std::cout << "MALFORMED SYSCALL EVENT (invalid pid field)" << std::endl;
        syscall_event.partial = true;
        continue;
      }

      syscall_event.process_id = static_cast<__pid_t>(process_id_value);
      syscall_event_list_[audit_event_record.audit_id] = syscall_event;

    } else if (audit_event_record.type == AUDIT_CWD) {
      if (audit_event_it == syscall_event_list_.end()) {
        std::cout << "MISSING EVENT! SKIPPING!" << std::endl;
        continue;
      }

      std::string field_value =
          L_GetFieldFromMap(audit_event_record.fields, "cwd", "");
      audit_event_it->second.cwd = field_value;

    } else if (audit_event_record.type == AUDIT_MMAP) {
      if (audit_event_it == syscall_event_list_.end()) {
        std::cout << "MISSING EVENT! SKIPPING!" << std::endl;
        continue;
      }

      std::string field_value =
          L_GetFieldFromMap(audit_event_record.fields, "fd", "");

      if (field_value.empty()) {
        std::cout << "MALFORMED MMAP EVENT (missing fd field)" << std::endl;
        audit_event_it->second.partial = true;

      } else {
        long long int mmap_fd;
        if (!safeStrtoll(field_value, 10, mmap_fd)) {
          std::cout << "MALFORMED MMAP EVENT (invalid fd field)" << std::endl;
          audit_event_it->second.partial = true;

        } else {
          audit_event_it->second.input_fd = static_cast<int>(mmap_fd);
        }
      }

    } else if (audit_event_record.type == AUDIT_PATH) {
      if (audit_event_it == syscall_event_list_.end()) {
        std::cout << "MISSING EVENT! SKIPPING!" << std::endl;
        continue;
      }

      std::string field_value =
          L_GetFieldFromMap(audit_event_record.fields, "name", "NOT FOUND");
      audit_event_it->second.path = field_value;

    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == syscall_event_list_.end()) {
        std::cout << "MISSING EVENT! SKIPPING!" << std::endl;
        continue;
      }

      auto completed_syscall_event = audit_event_it->second;
      syscall_event_list_.erase(audit_event_it);

      if (FLAGS_audit_fim_debug) {
        std::cout << completed_syscall_event << std::endl;
      }

      event_context->syscall_events.push_back(completed_syscall_event);
    }
  }

  if (!event_context->syscall_events.empty()) {
    fire(event_context);

    for (const auto& syscall_event : event_context->syscall_events) {
      std::cout << syscall_event << "\n";
    }

    std::cout << std::endl;
  }

  return Status(0, "OK");
}

bool AuditFimEventPublisher::shouldFire(
    const AuditFimSubscriptionContextRef& sc,
    const AuditFimEventContextRef& ec) const {
  return true;
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
