/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/events/linux/auditd_fim_events.h"

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include <boost/filesystem/operations.hpp>

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

      configuration_.included_path_list.reserve(
          configuration_.included_path_list.size() + solved_path_list.size());
      configuration_.included_path_list.insert(
          configuration_.included_path_list.end(),
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

      configuration_.excluded_path_list.resize(
          configuration_.excluded_path_list.size() +
          configuration_.excluded_path_list.size());
      configuration_.excluded_path_list.insert(
          configuration_.excluded_path_list.end(),
          solved_path_list.begin(),
          solved_path_list.end());
    }
  }

  if (root_key.find("show_accesses") != root_key.not_found()) {
    auto key = root_key.get_child("show_accesses");
    auto value = key.get_value<std::string>();

    configuration_.show_accesses = (value == "true");
  }
}

Status AuditdFimEventSubscriber::Callback(const ECRef& event_context,
                                          const SCRef& subscription_context) {
  std::vector<Row> emitted_row_list;
  auto exit_status = ProcessEvents(emitted_row_list,
                                   process_map_,
                                   configuration_,
                                   event_context->syscall_events);

  for (auto& row : emitted_row_list) {
    add(row);
  }

  return exit_status;
}

Status AuditdFimEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    AuditdFimProcessMap& process_map,
    const AuditdFimConfiguration& configuration,
    const std::vector<SyscallEvent>& syscall_event_list) noexcept {
  // Configuration helpers
  auto L_isPathIncluded = [&configuration](const std::string& path) -> bool {
    return (std::find(configuration.included_path_list.begin(),
                      configuration.included_path_list.end(),
                      path) != configuration.included_path_list.end());
  };

  auto L_isPathExcluded = [&configuration](const std::string& path) -> bool {
    return (std::find(configuration.excluded_path_list.begin(),
                      configuration.excluded_path_list.end(),
                      path) != configuration.excluded_path_list.end());
  };

  // Path normalization utility
  auto L_normalizePath = [](const std::string& cwd,
                            const std::string& path) -> std::string {
    std::string translated_path;

    // Remove the surrounding quotes, if any (they are only present if
    // the path contains spaces)
    if (path[0] == '"') {
      translated_path = path.substr(1, path.size() - 2);
    } else {
      translated_path = path;
    }

    // Also use the working directory if the path is not absolute
    if (translated_path[0] != '/') {
      std::string translated_cwd;

      if (cwd[0] == '"') {
        translated_cwd = cwd.substr(1, cwd.size() - 2);
      } else {
        translated_cwd = cwd;
      }

      translated_path = translated_cwd + "/" + translated_path;
    }

    // Normalize the path; we could have used 'canonicalize()' but that
    // accesses the file system and we don't want that (because it may
    // spawn other events). It is also possible that by the time we
    // inspect the files on disk the state that caused this event has
    // changed.
    namespace boostfs = boost::filesystem;
    boostfs::path normalized_path(translated_path);
    normalized_path = normalized_path.normalize();

    return normalized_path.string();
  };

  emitted_row_list.clear();

  // Process the syscall events we received and emit the necessary rows
  for (const SyscallEvent& syscall : syscall_event_list) {
    auto syscall_type = syscall.type;

    switch (syscall_type) {
    case SyscallEvent::Type::Execve: {
      // Allocate a new handle table
      process_map[syscall.process_id] = AuditdFimProcessState();
      break;
    }

    // We just have to drop the file descriptor table for the exiting process
    case SyscallEvent::Type::Exit:
    case SyscallEvent::Type::Exit_group: {
      // This process may have been created before us, so we may not have
      // a handle table to drop
      auto handle_map_it = process_map.find(syscall.process_id);
      if (handle_map_it != process_map.end()) {
        process_map.erase(handle_map_it);
      }

      break;
    }

    /*
      name_to_handle_at contains both the path and inode of the file.

      The open_by_handle_at() outputs a file descriptor, but to find the
      path we need to match the inode.

      Pseudo code:
        struct file_handle h;
        name_to_handle_at("/path", &h); // AUDIT_PATH with name + inode
        int fd = open_by_handle_at(&h); // AUDIT_PATH with just the inode
    */

    case SyscallEvent::Type::Name_to_handle_at: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);
      }

      AuditdFimFileInodeMap& file_inode_map =
          process_state_it->second.inode_map;
      file_inode_map[syscall.file_inode].path = syscall.path;
      file_inode_map[syscall.file_inode].cwd = syscall.cwd;

      // Limit the amount of inodes we are going to track
      if (file_inode_map.size() > 4096) {
        file_inode_map.erase(file_inode_map.begin());
      }

      break;
    }

    // See how the name_to_handle_at syscall above is handled
    case SyscallEvent::Type::Open_by_handle_at: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);
      }

      const auto& file_struct_map = process_state_it->second.inode_map;

      auto inode_it = file_struct_map.find(syscall.file_inode);
      if (inode_it == file_struct_map.end()) {
        VLOG(1) << "Untracked open_by_handle_at syscall received. Subsequent "
                   "calls on this handle will be shown as partials";

        break;
      }

      AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
      std::string translated_path =
          L_normalizePath(inode_it->second.cwd, inode_it->second.path);

      // update the handle table
      HandleInformation handle_info;
      handle_info.last_operation = HandleInformation::OperationType::Open;
      handle_info.path = translated_path;

      handle_map[syscall.output_fd] = handle_info;

      // collect the event, if necessary
      if (configuration.show_accesses && !L_isPathExcluded(handle_info.path) &&
          L_isPathIncluded(handle_info.path)) {
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
        row["executable"] = syscall.executable_path;
        row["partial"] = (syscall.partial ? "true" : "false");
        emitted_row_list.push_back(row);
      }

      break;
    }

    // Find the handle table for the process, and then lookup the file
    // descriptor
    case SyscallEvent::Type::Creat:
    case SyscallEvent::Type::Mknod:
    case SyscallEvent::Type::Mknodat:
    case SyscallEvent::Type::Open:
    case SyscallEvent::Type::Openat: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);
      }

      AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
      std::string translated_path = L_normalizePath(syscall.cwd, syscall.path);

      // update the handle table
      HandleInformation handle_info;
      handle_info.last_operation = HandleInformation::OperationType::Open;
      handle_info.path = translated_path;

      handle_map[syscall.output_fd] = handle_info;

      // collect the event, if necessary
      if (configuration.show_accesses && !L_isPathExcluded(handle_info.path) &&
          L_isPathIncluded(handle_info.path)) {
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
        row["executable"] = syscall.executable_path;
        row["partial"] = (syscall.partial ? "true" : "false");
        emitted_row_list.push_back(row);
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

      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);

        partial_event = true;
      }

      if (configuration.show_accesses) {
        Row row;

        /// attempt to solve the file descriptor
        AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
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
          discard_event = (L_isPathExcluded(row["canonical_path"]) ||
                           !L_isPathIncluded(row["canonical_path"]));
        }

        if (!discard_event) {
          row["syscall"] = "close";
          row["pid"] = std::to_string(syscall.process_id);
          row["ppid"] = std::to_string(syscall.parent_process_id);
          row["uptime"] = std::to_string(tables::getUptime());
          row["input_fd"] = std::to_string(syscall.input_fd);
          row["output_fd"] = "";
          row["executable"] = syscall.executable_path;

          // the following fields are not known for this type of event
          row["cwd"] = "";
          row["name"] = "";

          row["partial"] = (partial_event ? "true" : "false");

          emitted_row_list.push_back(row);
        }
      }

      break;
    }

    // Find the handle table for the process, and duplicate the specified file
    // descriptor
    case SyscallEvent::Type::Dup: {
      // Allocate a new handle map if this process has been created before
      // osquery
      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);
        break;
      }

      AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
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
      auto process_state_it = process_map.find(syscall.process_id);
      if (process_state_it == process_map.end()) {
        if (!FLAGS_audit_show_partial_file_events) {
          break;
        }

        process_map[syscall.process_id] = AuditdFimProcessState();
        process_state_it = process_map.find(syscall.process_id);

        partial_event = true;
      }

      // attempt to solve the file descriptor
      AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
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
      // to "write" The "written" state means that the file has also been
      // read; this means that we will not notify about this file again until
      // it is re-opened

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

      if (!read_operation || configuration.show_accesses) {
        if (partial_event) {
          discard_event = false;
        } else {
          discard_event = (L_isPathExcluded(handle_info->path) ||
                           !L_isPathIncluded(handle_info->path));
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
        row["executable"] = syscall.executable_path;
        row["partial"] = (partial_event ? "true" : "false");

        // the following fields are not known for this type of event
        row["cwd"] = "";
        row["name"] = "";

        emitted_row_list.push_back(row);
      }

      break;
    }

    case SyscallEvent::Type::Invalid: {
      return Status(1, "Invalid event type");
    }
    }
  }

  // If we have lost audit event records (i.e.: the kernel queue is smaller
  // than the system activity) we may end up having orphaned process entries.
  //
  // Erase the objects that no longer have a valid process id
  for (auto it = process_map.begin(); it != process_map.end();) {
    if (getpgid(it->first) != static_cast<__pid_t>(-1)) {
      it++;
    } else if (errno == ESRCH) {
      it = process_map.erase(it);
    }
  }

  return Status(0, "OK");
}
}
