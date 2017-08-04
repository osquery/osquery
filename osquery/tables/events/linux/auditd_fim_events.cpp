/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem/operations.hpp>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/tables/events/linux/auditd_fim_events.h"

namespace boostfs = boost::filesystem;

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

namespace {
std::string NormalizePath(const std::string& cwd,
                          const std::string& path) noexcept {
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

    translated_path = translated_cwd + '/' + translated_path;
  }

  /*
    Normalize the path; we could have used 'canonicalize()' but that
    accesses the file system and we don't want that (because it may
    spawn other events). It is also possible that by the time we
    inspect the files on disk the state that caused this event has
    changed.
  */

  boostfs::path normalized_path(translated_path);
  normalized_path = normalized_path.normalize();

  return normalized_path.string();
};
}

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

  emitted_row_list.clear();

  // Process the syscall events we received and emit the necessary rows
  for (const SyscallEvent& syscall_event : syscall_event_list) {
    auto syscall_type = syscall_event.type;

    switch (syscall_type) {
    case SyscallEvent::Type::Execve: {
      auto unused =
          GetOrCreateProcessState(process_map, syscall_event.process_id, true);
      static_cast<void>(unused);
      break;
    }

    case SyscallEvent::Type::Exit:
    case SyscallEvent::Type::Exit_group: {
      DropProcessState(process_map, syscall_event.process_id);
      break;
    }

    case SyscallEvent::Type::Name_to_handle_at: {
      SaveInodeInformation(process_map,
                           syscall_event.process_id,
                           syscall_event.file_inode,
                           syscall_event.cwd,
                           syscall_event.path);
      break;
    }

    case SyscallEvent::Type::Open_by_handle_at: {
      AuditdFimPathInformation inode_info;
      if (!GetInodeInformation(process_map,
                               syscall_event.process_id,
                               syscall_event.file_inode,
                               inode_info)) {
        VLOG(1) << "Untracked open_by_handle_at syscall received. Subsequent "
                   "calls on this handle will be shown as partials";

        break;
      }

      std::string normalized_path =
          NormalizePath(inode_info.cwd, inode_info.path);
      SaveHandleInformation(process_map,
                            syscall_event.process_id,
                            static_cast<std::uint64_t>(syscall_event.output_fd),
                            normalized_path,
                            AuditdFimHandleInformation::OperationType::Open);

      if (configuration.show_accesses && !L_isPathExcluded(normalized_path) &&
          L_isPathIncluded(normalized_path)) {
        Row row;
        row["syscall"] = "open";
        row["pid"] = std::to_string(syscall_event.process_id);
        row["ppid"] = std::to_string(syscall_event.parent_process_id);
        row["cwd"] = syscall_event.cwd;
        row["name"] = syscall_event.path;
        row["canonical_path"] = normalized_path;
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = "";
        row["output_fd"] = std::to_string(syscall_event.output_fd);
        row["executable"] = syscall_event.executable_path;
        row["partial"] = (syscall_event.partial ? "true" : "false");
        emitted_row_list.push_back(row);
      }

      break;
    }

    case SyscallEvent::Type::Unlink:
    case SyscallEvent::Type::Unlinkat: {
      auto normalized_path =
          NormalizePath(syscall_event.cwd, syscall_event.path);

      if (!L_isPathExcluded(normalized_path) &&
          L_isPathIncluded(normalized_path)) {
        Row row;
        row["syscall"] = "unlink";
        row["pid"] = std::to_string(syscall_event.process_id);
        row["ppid"] = std::to_string(syscall_event.parent_process_id);
        row["cwd"] = syscall_event.cwd;
        row["name"] = syscall_event.path;
        row["canonical_path"] = normalized_path;
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = "";
        row["output_fd"] = "";
        row["executable"] = syscall_event.executable_path;
        row["partial"] = "false";
        emitted_row_list.push_back(row);
      }

      break;
    }

    case SyscallEvent::Type::Creat:
    case SyscallEvent::Type::Mknod:
    case SyscallEvent::Type::Mknodat:
    case SyscallEvent::Type::Open:
    case SyscallEvent::Type::Openat: {
      std::string normalized_path =
          NormalizePath(syscall_event.cwd, syscall_event.path);
      SaveHandleInformation(process_map,
                            syscall_event.process_id,
                            static_cast<std::uint64_t>(syscall_event.output_fd),
                            normalized_path,
                            AuditdFimHandleInformation::OperationType::Open);

      if (configuration.show_accesses && !L_isPathExcluded(normalized_path) &&
          L_isPathIncluded(normalized_path)) {
        Row row;
        row["syscall"] = "open";
        row["pid"] = std::to_string(syscall_event.process_id);
        row["ppid"] = std::to_string(syscall_event.parent_process_id);
        row["cwd"] = syscall_event.cwd;
        row["name"] = syscall_event.path;
        row["canonical_path"] = normalized_path;
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = "";
        row["output_fd"] = std::to_string(syscall_event.output_fd);
        row["executable"] = syscall_event.executable_path;
        row["partial"] = (syscall_event.partial ? "true" : "false");
        emitted_row_list.push_back(row);
      }

      break;
    }

    case SyscallEvent::Type::Close: {
      auto fd = static_cast<std::uint64_t>(syscall_event.input_fd);

      AuditdFimHandleInformation handle_info;
      if (!GetHandleInformation(
              process_map, syscall_event.process_id, fd, handle_info)) {
        break;
      }

      DropHandleInformation(process_map, syscall_event.process_id, fd);
      if (!configuration.show_accesses) {
        break;
      }

      if (!L_isPathExcluded(handle_info.path) &&
          L_isPathIncluded(handle_info.path)) {
        Row row;
        row["canonical_path"] = handle_info.path;
        row["syscall"] = "close";
        row["pid"] = std::to_string(syscall_event.process_id);
        row["ppid"] = std::to_string(syscall_event.parent_process_id);
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = std::to_string(syscall_event.input_fd);
        row["output_fd"] = "";
        row["executable"] = syscall_event.executable_path;
        row["cwd"] = "";
        row["name"] = "";
        row["partial"] = "false";

        emitted_row_list.push_back(row);
      }

      break;
    }

    case SyscallEvent::Type::Dup: {
      auto fd = static_cast<std::uint64_t>(syscall_event.input_fd);

      AuditdFimHandleInformation handle_info;
      if (!GetHandleInformation(
              process_map, syscall_event.process_id, fd, handle_info)) {
        break;
      }

      SaveHandleInformation(process_map,
                            syscall_event.process_id,
                            fd,
                            handle_info.path,
                            handle_info.last_operation);
      break;
    }

    // Handle the mmap syscall like a read or write operation, depending on the
    // memory protection flags
    case SyscallEvent::Type::Mmap:
      syscall_type =
          ((syscall_event.mmap_memory_protection_flags & PROT_WRITE) != 0
               ? SyscallEvent::Type::Write
               : SyscallEvent::Type::Read);

    case SyscallEvent::Type::Read:
    case SyscallEvent::Type::Write: {
      auto fd = static_cast<std::uint64_t>(syscall_event.input_fd);

      AuditdFimHandleInformation handle_info;
      if (!GetHandleInformation(
              process_map, syscall_event.process_id, fd, handle_info)) {
        break;
      }

      bool read_operation = (syscall_type == SyscallEvent::Type::Read);

      /*
        Only save state changes from "open" to "read or write" and from "read"
        to "write". The "written" state means that the file may has also have
        been read; in this case, we will not notify about this file again
        until it is closed and opened again
      */

      // Advance the file state
      bool discard_event = true;

      if (handle_info.last_operation ==
          AuditdFimHandleInformation::OperationType::Open) {
        discard_event = false;

        handle_info.last_operation =
            (read_operation ? AuditdFimHandleInformation::OperationType::Read
                            : AuditdFimHandleInformation::OperationType::Write);
      }

      else if (!read_operation &&
               handle_info.last_operation ==
                   AuditdFimHandleInformation::OperationType::Read) {
        discard_event = false;
        handle_info.last_operation =
            AuditdFimHandleInformation::OperationType::Write;
      }

      SaveHandleInformation(process_map,
                            syscall_event.process_id,
                            fd,
                            handle_info.path,
                            handle_info.last_operation);

      if (discard_event || !configuration.show_accesses) {
        break;
      }

      if (!L_isPathExcluded(handle_info.path) &&
          L_isPathIncluded(handle_info.path)) {
        Row row;
        row["canonical_path"] = handle_info.path;
        row["syscall"] = (read_operation ? "read" : "write");
        row["pid"] = std::to_string(syscall_event.process_id);
        row["ppid"] = std::to_string(syscall_event.parent_process_id);
        row["uptime"] = std::to_string(tables::getUptime());
        row["input_fd"] = std::to_string(syscall_event.input_fd);
        row["output_fd"] = "";
        row["executable"] = syscall_event.executable_path;
        row["partial"] = "false";
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

  /*
    If we have lost audit event records (i.e.: the kernel queue is smaller
    than the system activity) we may end up having orphaned process entries.

    Erase the objects that no longer have a valid process id
  */

  for (auto it = process_map.begin(); it != process_map.end();) {
    if (getpgid(it->first) != static_cast<__pid_t>(-1)) {
      it++;
    } else if (errno == ESRCH) {
      it = process_map.erase(it);
    }
  }

  return Status(0, "OK");
}

AuditdFimProcessMap::iterator AuditdFimEventSubscriber::GetOrCreateProcessState(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    bool create_if_missing) noexcept {
  auto it = process_map.find(process_id);
  if (it == process_map.end() && create_if_missing) {
    it = process_map.insert({process_id, AuditdFimProcessState()}).first;
  }

  return it;
}

void AuditdFimEventSubscriber::DropProcessState(
    AuditdFimProcessMap& process_map, __pid_t process_id) noexcept {
  auto it = process_map.find(process_id);
  if (it != process_map.end()) {
    process_map.erase(it);
  }
}

void AuditdFimEventSubscriber::SaveInodeInformation(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    __ino_t inode,
    const std::string& cwd,
    const std::string& path) noexcept {
  auto process_state_it =
      GetOrCreateProcessState(process_map, process_id, true);

  AuditdFimFileInodeMap& file_inode_map = process_state_it->second.inode_map;
  file_inode_map[inode] = {cwd, path};

  // Limit the amount of inodes we are going to track
  if (file_inode_map.size() > 4096) {
    file_inode_map.erase(file_inode_map.begin());
  }
}

bool AuditdFimEventSubscriber::GetInodeInformation(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    __ino_t inode,
    AuditdFimPathInformation& path_information) noexcept {
  path_information = {};

  auto process_state_it =
      GetOrCreateProcessState(process_map, process_id, true);

  const AuditdFimFileInodeMap& inode_map = process_state_it->second.inode_map;
  auto it = inode_map.find(inode);
  if (it == inode_map.end()) {
    return false;
  }

  path_information = it->second;
  return true;
}

void AuditdFimEventSubscriber::SaveHandleInformation(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    std::uint64_t fd,
    const std::string& path,
    AuditdFimHandleInformation::OperationType last_operation) noexcept {
  auto process_state_it =
      GetOrCreateProcessState(process_map, process_id, true);

  AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
  handle_map[fd] = {last_operation, path};
}

bool AuditdFimEventSubscriber::GetHandleInformation(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    std::uint64_t fd,
    AuditdFimHandleInformation& handle_info) noexcept {
  handle_info = {};

  auto process_state_it =
      GetOrCreateProcessState(process_map, process_id, false);
  if (process_state_it == process_map.end()) {
    return false;
  }

  AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
  auto it = handle_map.find(fd);
  if (it == handle_map.end()) {
    return false;
  }

  handle_info = it->second;
  return true;
}

void AuditdFimEventSubscriber::DropHandleInformation(
    AuditdFimProcessMap& process_map,
    __pid_t process_id,
    std::uint64_t fd) noexcept {
  auto process_state_it =
      GetOrCreateProcessState(process_map, process_id, false);
  if (process_state_it == process_map.end()) {
    return;
  }

  AuditdFimHandleMap& handle_map = process_state_it->second.handle_map;
  auto it = handle_map.find(fd);
  if (it != handle_map.end()) {
    handle_map.erase(it);
  }
}
}
