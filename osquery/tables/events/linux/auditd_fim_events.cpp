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

#include <osquery/config.h>
#include <osquery/events.h>
#include <osquery/filesystem.h>
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
     audit_allow_fim_events,
     false,
     "Allow the audit publisher to install file event monitoring rules");

FLAG(bool,
     audit_show_partial_file_events,
     false,
     "Allow the audit publisher to show partial file events");

/// This structure stores the information for a tracked file handle
struct HandleInformation final {
  /// Operation type affecting this file handle
  enum class OperationType { Open, Read, Write };

  /// The last operation executed on this file handle; this is used by the
  /// filtering logic to reduce output
  OperationType last_operation{OperationType::Open};

  /// The path for this file handle
  std::string path;
};

/// Holds the file descriptor map for a process
using HandleMap = std::unordered_map<int, HandleInformation>;

/// Holds the file descriptor maps for all processes
using ProcessMap = std::unordered_map<__pid_t, HandleMap>;

/// A simple vector of strings
using StringList = std::vector<std::string>;

class AuditdFimEventSubscriber final
    : public EventSubscriber<AuditdFimEventPublisher> {
  ProcessMap process_map_;
  StringList included_path_list_;
  StringList excluded_path_list_;
  bool show_accesses_{true};

 public:
  Status setUp() override;
  Status init() override;
  void configure() override;

  Status Callback(const ECRef& event_context,
                  const SCRef& subscription_context);

 private:
  bool isPathIncluded(const std::string& path) const noexcept;
  bool isPathExcluded(const std::string& path) const noexcept;
};

REGISTER(AuditdFimEventSubscriber, "event_subscriber", "auditd_fim_events");

Status AuditdFimEventSubscriber::setUp() {
  if (!FLAGS_audit_allow_fim_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  return Status(0);
}

Status AuditdFimEventSubscriber::init() {
  auto sc = createSubscriptionContext();
  subscribe(&AuditdFimEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

void AuditdFimEventSubscriber::configure() {
  auto parser = Config::getParser("auditd_fim");
  const auto& root_key = parser.get()->getData();

  if (root_key.find("include") != root_key.not_found()) {
    for (auto& path_value : root_key.get_child("include")) {
      auto pattern = path_value.second.data();
      replaceGlobWildcards(pattern);

      StringList solved_path_list = {};
      resolveFilePattern(pattern, solved_path_list);

      included_path_list_.reserve(included_path_list_.size() +
                                  solved_path_list.size());
      included_path_list_.insert(included_path_list_.end(),
                                 solved_path_list.begin(),
                                 solved_path_list.end());
    }
  }

  if (root_key.find("exclude") != root_key.not_found()) {
    for (auto& path_value : root_key.get_child("exclude")) {
      auto pattern = path_value.second.data();
      replaceGlobWildcards(pattern);

      StringList solved_path_list = {};
      resolveFilePattern(pattern, solved_path_list);

      excluded_path_list_.resize(excluded_path_list_.size() +
                                 excluded_path_list_.size());
      excluded_path_list_.insert(excluded_path_list_.end(),
                                 solved_path_list.begin(),
                                 solved_path_list.end());
    }
  }

  if (root_key.find("show_accesses") != root_key.not_found()) {
    auto key = root_key.get_child("show_accesses");
    auto value = key.get_value<std::string>();

    show_accesses_ = (value == "true");
  }
}

Status AuditdFimEventSubscriber::Callback(const ECRef& event_context,
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

      // normalize the path
      std::string path = syscall.path;
      if (syscall.path[0] == '"') {
        path = syscall.path.substr(1, syscall.path.size() - 2);
      } else {
        path = syscall.path;
      }

      if (path[0] != '/') {
        std::string cwd;

        if (syscall.cwd[0] == '"') {
          cwd = syscall.cwd.substr(1, syscall.cwd.size() - 2);
        } else {
          cwd = syscall.cwd;
        }

        path = cwd + "/" + path;
      }

      namespace boostfs = boost::filesystem;
      boostfs::path translated_path(path);
      translated_path = translated_path.normalize();

      // update the handle table
      HandleInformation handle_info;
      handle_info.last_operation = HandleInformation::OperationType::Open;
      handle_info.path = translated_path.string();

      handle_map[syscall.output_fd] = handle_info;

      // collect the event, if necessary
      if (show_accesses_ && !isPathExcluded(handle_info.path) &&
          isPathIncluded(handle_info.path)) {
        Row row;
        row["syscall"] = "open";
        row["pid"] = std::to_string(syscall.process_id);
        row["ppid"] = std::to_string(syscall.parent_process_id);
        row["cwd"] = syscall.cwd;
        row["name"] = syscall.path;
        row["canonical_path"] = handle_info.path;
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = "";
        row["output_fd"] = std::to_string(syscall.output_fd);
        row["success"] = syscall.success;
        row["executable"] = syscall.executable_path;
        row["partial"] = (syscall.partial ? "true" : "false");
        add(row);
      }

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

      if (show_accesses_) {
        Row row;

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

        bool discard_event;
        if (partial_event) {
          discard_event = !FLAGS_audit_show_partial_file_events;
        } else {
          discard_event = (isPathExcluded(row["canonical_path"]) ||
                           !isPathIncluded(row["canonical_path"]));
        }

        if (!discard_event) {
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

          row["partial"] = (partial_event ? "true" : "false");

          add(row);
        }
      }

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

      // Discard this right away if we do not allow partial events
      auto handle_map_it = process_map_.find(syscall.process_id);
      if (handle_map_it == process_map_.end()) {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        process_map_[syscall.process_id] = HandleMap();
        handle_map_it = process_map_.find(syscall.process_id);

        partial_event = true;
      }

      // attempt to solve the file descriptor
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

      // Only show state changes from "open" to "read or write" and from "read"
      // to
      // "write"
      // The "written" state means that the file has also been read; this means
      // that we will not notify about this file again until it is re-opened

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

      //
      // check the filters
      //

      discard_event = true;

      if (!read_operation || show_accesses_) {
        if (partial_event) {
          discard_event = false;
        } else {
          discard_event = (isPathExcluded(handle_info->path) ||
                           !isPathIncluded(handle_info->path));
        }
      }

      if (!discard_event) {
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
      }

      break;
    }

    case SyscallEvent::Type::Invalid: {
      return Status(1, "Invalid event type");
    }
    }
  }

  return Status(0, "OK");
}

bool AuditdFimEventSubscriber::isPathIncluded(const std::string& path) const
    noexcept {
  return (std::find(included_path_list_.begin(),
                    included_path_list_.end(),
                    path) != included_path_list_.end());
}

bool AuditdFimEventSubscriber::isPathExcluded(const std::string& path) const
    noexcept {
  return (std::find(excluded_path_list_.begin(),
                    excluded_path_list_.end(),
                    path) != excluded_path_list_.end());
}
}
