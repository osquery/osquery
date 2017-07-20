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

#include <osquery/config.h>
#include <osquery/events.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include <asm/unistd_64.h>

#include <boost/filesystem/operations.hpp>

#include <iostream>
#include <unordered_map>

namespace osquery {
// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

FLAG(bool,
     audit_allow_file_events,
     false,
     "Allow the audit publisher to install file event monitoring rules");

FLAG(bool,
     audit_show_partial_file_events,
     true,
     "Allow the audit publisher to show partial file events");

struct HandleInformation final {
  enum class OperationType { Open, Read, Write };

  OperationType last_operation{OperationType::Open};
  std::string path;
};

typedef std::unordered_map<int, HandleInformation> HandleMap;
typedef std::unordered_map<__pid_t, HandleMap> ProcessMap;

class AuditFimEventSubscriber : public EventSubscriber<AuditFimEventPublisher> {
  ProcessMap process_map_;

 public:
  Status setUp() override;
  Status init() override;
  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);
};

REGISTER(AuditFimEventSubscriber, "event_subscriber", "auditd_file_events");

Status AuditFimEventSubscriber::setUp() {
  if (!FLAGS_audit_allow_file_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  return Status(0);
}

Status AuditFimEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  subscribe(&AuditFimEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status AuditFimEventSubscriber::Callback(const ECRef& event_context,
                                         const SCRef& subscription_context) {
  for (const SyscallEvent& syscall : event_context->syscall_events) {
    auto syscall_type = syscall.type;

    switch (syscall_type) {
    case SyscallEvent::Type::Execve: {
      // Allocate a new handle table
      process_map_[syscall.process_id] = HandleMap();
      break;
    }

    // We just have to drop the file descriptor table for the exiting process
    case SyscallEvent::Type::Exit:
    case SyscallEvent::Type::Exit_group: {
      /// \todo The exit_group should probably be treated differently

      // This process may have been created before us, so we may not have
      // a handle table to drop
      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it != process_map_.end()) {
        process_map_.erase(handle_map_it);
      }

      break;
    }

    // Find the handle table for the process, and then lookup the file
    // descriptor
    case SyscallEvent::Type::Open:
    case SyscallEvent::Type::Openat:
    case SyscallEvent::Type::Open_by_handle_at: {
      /// \todo The openat and open_by_handle_at are probably broken

      // Allocate a new handle map if this process has been created before
      // osquery
      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);
      }

      HandleMap& handle_map = handle_map_it->second;

      namespace boostfs = boost::filesystem;
      boostfs::path translated_path;

      try {
        translated_path = boostfs::canonical(boostfs::path(syscall.path),
                                             boostfs::path(syscall.cwd));
      } catch (...) {
        translated_path = boostfs::path(syscall.path).normalize();
      }

      HandleInformation handle_info;
      handle_info.last_operation = HandleInformation::OperationType::Open;
      handle_info.path = translated_path.string();

      handle_map[syscall.output_fd] = handle_info;

      Row row;
      row["syscall"] = "open";
      row["pid"] = std::to_string(syscall.process_id);
      row["ppid"] = std::to_string(syscall.parent_process_id);
      row["cwd"] = syscall.cwd;
      row["name"] = syscall.path;
      row["canonical_path"] = translated_path.string();
      row["uptime"] = std::to_string(tables::getUptime());
      row["input_fd"] = "";
      row["output_fd"] = std::to_string(syscall.output_fd);
      row["success"] = syscall.success;
      row["executable"] = syscall.executable_path;
      row["partial"] = (syscall.partial ? "true" : "false");
      add(row);

      break;
    }

    // Find the handle table for the process, and drop the specified file
    // descriptor
    case SyscallEvent::Type::Close: {
      // Allocate a new handle map if this process has been created before
      // osquery
      bool partial_event = syscall.partial;
      if (partial_event && !FLAGS_audit_show_partial_file_events) {
        break;
      }

      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);

        partial_event = true;
      }

      Row row;
      row["syscall"] = "close";
      row["pid"] = std::to_string(syscall.process_id);
      row["ppid"] = std::to_string(syscall.parent_process_id);
      row["uptime"] = std::to_string(tables::getUptime());
      row["input_fd"] = std::to_string(syscall.input_fd);
      row["output_fd"] = "";
      row["success"] = syscall.success;
      row["executable"] = syscall.executable_path;

      // the following fields are not known for this type of event
      row["cwd"] = "";
      row["name"] = "";

      /// attempt to solve the file descriptor
      HandleMap& handle_map = handle_map_it->second;
      auto file_name_it = handle_map.find(syscall.input_fd);
      if (file_name_it != handle_map.end()) {
        const HandleInformation& handle_info = file_name_it->second;
        row["canonical_path"] = handle_info.path;
        handle_map.erase(file_name_it);

      } else {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        row["canonical_path"] = "";
        partial_event = true;
      }

      row["partial"] = (partial_event ? "true" : "false");

      add(row);
      break;
    }

    // Find the handle table for the process, and duplicate the specified file
    // descriptor
    case SyscallEvent::Type::Dup: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);
        break;
      }

      HandleMap& handle_map = handle_map_it->second;
      auto file_name_it = handle_map.find(syscall.input_fd);
      if (file_name_it != handle_map.end()) {
        handle_map[syscall.output_fd] = file_name_it->second;
      }

      break;
    }

    // For the time being, remap this to a read or write, depending on the
    // requested memory protection
    case SyscallEvent::Type::Mmap: {
      bool write_memory_protection =
          ((syscall.mmap_memory_protection_flags & PROT_WRITE) != 0);
      syscall_type = (write_memory_protection ? SyscallEvent::Type::Write
                                              : SyscallEvent::Type::Read);

      // fall through here! we need to reach the Read and Write cases
    }

    case SyscallEvent::Type::Read:
    case SyscallEvent::Type::Write: {
      bool read_operation = (syscall.type == SyscallEvent::Type::Read);

      // Allocate a new handle map if this process has been created before
      // osquery
      bool partial_event = syscall.partial;
      if (partial_event && !FLAGS_audit_show_partial_file_events) {
        break;
      }

      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);

        partial_event = true;
      }

      /// attempt to solve the file descriptor
      HandleMap& handle_map = handle_map_it->second;
      HandleInformation* handle_info = nullptr;

      auto file_info_it = handle_map.find(syscall.input_fd);
      if (file_info_it != handle_map.end()) {
        handle_info = &file_info_it->second;

      } else {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        partial_event = true;
      }

      // Only show state changes from "open" to "whatever" and from "read" to
      // "write"
      // The "written" state means that the file has also been read; this means
      // that we will not
      // notify about this file again until it is re-opened
      bool discard_event = true;
      if (partial_event || handle_info == nullptr) {
        discard_event = false;

      } else {
        // Always keep the first event
        if (handle_info->last_operation ==
            HandleInformation::OperationType::Open) {
          discard_event = false;
          handle_info->last_operation =
              (read_operation ? HandleInformation::OperationType::Read
                              : HandleInformation::OperationType::Write);
        }

        else if (handle_info->last_operation ==
                     HandleInformation::OperationType::Read &&
                 !read_operation) {
          discard_event = false;
          handle_info->last_operation = HandleInformation::OperationType::Write;
        }
      }

      if (discard_event) {
        break;
      }

      Row row;
      if (handle_info != nullptr) {
        row["canonical_path"] = handle_info->path;
      } else {
        row["canonical_path"] = "";
      }

      row["syscall"] = (read_operation ? "read" : "write");
      row["pid"] = std::to_string(syscall.process_id);
      row["ppid"] = std::to_string(syscall.parent_process_id);
      row["uptime"] = std::to_string(tables::getUptime());
      row["input_fd"] = std::to_string(syscall.input_fd);
      row["output_fd"] = "";
      row["success"] = syscall.success;
      row["executable"] = syscall.executable_path;
      row["partial"] = (partial_event ? "true" : "false");

      // the following fields are not known for this type of event
      row["cwd"] = "";
      row["name"] = "";

      add(row);
      break;
    }

    case SyscallEvent::Type::Invalid: {
      return Status(1, "Invalid event type");
    }
    }
  }

  return Status(0, "OK");
}
}
