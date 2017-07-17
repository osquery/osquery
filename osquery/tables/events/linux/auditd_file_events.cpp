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

typedef std::unordered_map<int, std::string> HandleMap;
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
    switch (syscall.type) {
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
        break;
      }

      /// \todo Canonicalize the path; we should attempt to avoid accessing the
      /// filesystem if possible
      HandleMap& handle_map = handle_map_it->second;
      handle_map[syscall.output_fd] = syscall.cwd + "|" + syscall.path;

      Row row;
      row["action"] = "open";
      row["pid"] = std::to_string(syscall.process_id);
      row["ppid"] = std::to_string(syscall.parent_process_id);
      row["cwd"] = syscall.cwd;
      row["name"] = syscall.path;
      row["canonical_path"] = handle_map[syscall.output_fd];
      row["uptime"] = std::to_string(tables::getUptime());
      add(row);

      break;
    }

    // Find the handle table for the process, and drop the specified file
    // descriptor
    case SyscallEvent::Type::Close: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);
        break;
      }

      Row row;
      row["action"] = "close";
      row["pid"] = std::to_string(syscall.process_id);
      row["ppid"] = std::to_string(syscall.parent_process_id);
      row["uptime"] = std::to_string(tables::getUptime());

      // the following fields are not known for this type of event
      row["cwd"] = "";
      row["name"] = "";

      /// attempt to solve the file descriptor
      HandleMap& handle_map = handle_map_it->second;
      auto file_name_it = handle_map.find(syscall.input_fd);
      if (file_name_it != handle_map.end()) {
        row["canonical_path"] = file_name_it->second;
        handle_map.erase(file_name_it);
      } else {
        row["canonical_path"] = "";
      }

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

    // Not yet implemented
    case SyscallEvent::Type::Read:
    case SyscallEvent::Type::Write:
    case SyscallEvent::Type::Mmap: {
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
