/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <asm/unistd_64.h>

#include <iostream>
#include <string>
#include <cstdint>

#include <boost/filesystem/operations.hpp>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
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
     audit_show_partial_fim_events,
     false,
     "Allow the audit publisher to show partial file events");

FLAG(bool,
     audit_fim_debug,
     false,
     "Show debug messages for the FIM table");

REGISTER(AuditdFimEventSubscriber, "event_subscriber", "auditd_fim_events");

namespace {
std::ostream &operator<<(std::ostream &stream, AuditdFimSyscallContext::Type type) {
  switch (type) {
    case AuditdFimSyscallContext::Type::Link: {
      stream << "Link";
      break;
    }

    case AuditdFimSyscallContext::Type::Symlink: {
      stream << "Symlink";
      break;
    }

    case AuditdFimSyscallContext::Type::Unlink: {
      stream << "Unlink";
      break;
    }

    case AuditdFimSyscallContext::Type::Rename: {
      stream << "Rename";
      break;
    }

    case AuditdFimSyscallContext::Type::Open: {
      stream << "Open";
      break;
    }

    case AuditdFimSyscallContext::Type::Close: {
      stream << "Close";
      break;
    }

    case AuditdFimSyscallContext::Type::Dup: {
      stream << "Dup";
      break;
    }

    case AuditdFimSyscallContext::Type::Read: {
      stream << "Read";
      break;
    }

    case AuditdFimSyscallContext::Type::Write: {
      stream << "Write";
      break;
    }

    case AuditdFimSyscallContext::Type::Mmap: {
      stream << "Mmap";
      break;
    }

    default: {
      stream << "Unknown";
      break;
    }
  }

  return stream;
}

std::ostream &operator<<(std::ostream &stream, const AuditdFimSyscallContext &syscall_context) {
  stream << "Type: " << syscall_context.type << " ProcessID: " << syscall_context.process_id << " ImagePath: " << syscall_context.executable_path << " Data: ";

  switch (syscall_context.type) {
    case AuditdFimSyscallContext::Type::Link: {
      stream << "Link";
      break;
    }

    case AuditdFimSyscallContext::Type::Symlink: {
      stream << "Symlink";
      break;
    }

    case AuditdFimSyscallContext::Type::Rename: {
      const auto &data = boost::get<AuditdFimRenameData>(syscall_context.syscall_data);
      stream << data.source << " -> " << data.destination;
      break;
    }

    case AuditdFimSyscallContext::Type::Unlink:
    case AuditdFimSyscallContext::Type::Read:
    case AuditdFimSyscallContext::Type::Write:
    case AuditdFimSyscallContext::Type::Open:
    case AuditdFimSyscallContext::Type::Close: {
      const auto &data = boost::get<AuditdFimIOData>(syscall_context.syscall_data);
      if (data.type == AuditdFimIOData::Type::Open) {
        stream << "Open ";
      } else if (data.type == AuditdFimIOData::Type::Read) {
        stream << "Read ";
      } else if (data.type == AuditdFimIOData::Type::Write) {
        stream << "Write ";
      } else if (data.type == AuditdFimIOData::Type::Unlink) {
        stream << "Unlink ";
      } else {
        stream << "Close ";
      }

      stream << data.target << " StateChange: " << (data.state_changed ? "True" : "False") << " ";
      break;
    }

    case AuditdFimSyscallContext::Type::Dup: {
      stream << "Dup";
      break;
    }

    case AuditdFimSyscallContext::Type::Mmap: {
      stream << "Mmap";
      break;
    }

    default: {
      stream << "Unknown";
      break;
    }
  }

  return stream;
}

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

AuditdFimFdMap *GetOrCreateProcessMap(AuditdFimContext &fim_context, pid_t process_id, bool create_if_missing = false) noexcept {
  auto it = fim_context.process_map.find(process_id);
  if (it == fim_context.process_map.end() && create_if_missing) {
    it = fim_context.process_map.insert({process_id, AuditdFimFdMap()}).first;
  }

  if (it != fim_context.process_map.end()) {
    return &it->second;
  } else {
    return nullptr;
  }
}

bool EmitRowFromSyscallContext(Row &row, AuditdFimSyscallContext &syscall_context) noexcept {
  row.clear();

  if (!FLAGS_audit_show_partial_fim_events && syscall_context.partial) {
    return false;
  }

  switch (syscall_context.type) {
    case AuditdFimSyscallContext::Type::Link: {
      row["operation"] = "link";
      return false;
    }

    case AuditdFimSyscallContext::Type::Symlink: {
      row["operation"] = "symlink";
      return false;
    }

    case AuditdFimSyscallContext::Type::Rename: {
      row["operation"] = "rename";

      const auto &data = boost::get<AuditdFimRenameData>(syscall_context.syscall_data);
      row["path1"] = data.source;
      row["path2"] = data.destination;

      break;
    }

    case AuditdFimSyscallContext::Type::Unlink:
    case AuditdFimSyscallContext::Type::Read:
    case AuditdFimSyscallContext::Type::Write:
    case AuditdFimSyscallContext::Type::Open:
    case AuditdFimSyscallContext::Type::Close: {
      const auto &data = boost::get<AuditdFimIOData>(syscall_context.syscall_data);
      if (!data.state_changed) {
        return false;
      }

      if (data.type == AuditdFimIOData::Type::Open) {
        row["operation"] = "open";
      } else if (data.type == AuditdFimIOData::Type::Read) {
        row["operation"] = "read";
      } else if (data.type == AuditdFimIOData::Type::Write) {
        row["operation"] = "write";
      } else if (data.type == AuditdFimIOData::Type::Unlink) {
        row["operation"] = "unlink";
      } else {
        row["operation"] = "close";
      }

      row["path1"] = data.target;
      break;
    }

    case AuditdFimSyscallContext::Type::Mmap: {
      return false;
    }

    default: {
      return false;
    }
  }

  row["pid"] = std::to_string(static_cast<std::uint64_t>(syscall_context.process_id));
  row["ppid"] = std::to_string(static_cast<std::uint64_t>(syscall_context.parent_process_id));
  row["executable"] = syscall_context.executable_path;
  row["partial"] = (syscall_context.partial ? "true" : "false");
  row["cwd"] = syscall_context.cwd;

  return true;
}

bool ParseAuditCwdRecord(std::string &cwd, const AuditEventRecord &record) noexcept {
  return GetStringFieldFromMap(cwd, record.fields, "cwd");
}

bool ParseAuditMmapRecord(const AuditEventRecord &record) noexcept {
  return true;
}

bool ParseAuditPathRecord(AuditdFimPathRecordItem &output, const AuditEventRecord &record) noexcept {
  std::uint64_t item_index;
  if (!GetIntegerFieldFromMap(item_index, record.fields, "item", 10))
    return false;

  std::uint64_t inode;
  if (!GetIntegerFieldFromMap(inode, record.fields, "inode", 10))
    return false;

  // The 'name' field is sometimes left blank (i.e.: open_by_handle_at)
  GetStringFieldFromMap(output.path, record.fields, "name");

  output.index = static_cast<std::size_t>(item_index);
  output.inode = static_cast<ino_t>(inode);

  return true;
}

bool HandleReadOrWriteSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  if (syscall_context.syscall_number == __NR_pread64 || syscall_context.syscall_number == __NR_preadv ||
      syscall_context.syscall_number == __NR_read || syscall_context.syscall_number == __NR_readv) {
    syscall_context.type = AuditdFimSyscallContext::Type::Read;
  } else {
    syscall_context.type = AuditdFimSyscallContext::Type::Write;
  }

  std::uint64_t fd;
  if (!GetIntegerFieldFromMap(fd, record.fields, "a0")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
            "file descriptor field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdMap &fd_map = *GetOrCreateProcessMap(fim_context, syscall_context.process_id, true);

  auto fd_desc_it = fd_map.find(fd);
  if (fd_desc_it == fd_map.end()) {
    VLOG(1) << "Untracked file descriptor";
    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdDescriptor &fd_desc = fd_desc_it->second;
  bool state_changed = false;

  switch (fd_desc.last_operation) {
    case AuditdFimFdDescriptor::OperationType::Open: {
      if (syscall_context.type == AuditdFimSyscallContext::Type::Read) {
        fd_desc.last_operation = AuditdFimFdDescriptor::OperationType::Read;
      } else {
        fd_desc.last_operation = AuditdFimFdDescriptor::OperationType::Write;
      }

      state_changed = true;
      break;
    }

    case AuditdFimFdDescriptor::OperationType::Read: {
      if (syscall_context.type == AuditdFimSyscallContext::Type::Write) {
        fd_desc.last_operation = AuditdFimFdDescriptor::OperationType::Write;
        state_changed = true;
      }

      break;
    }

    case AuditdFimFdDescriptor::OperationType::Write: {
      break;
    }
  }

  auto inode_desc_it = fim_context.inode_map.find(fd_desc.inode);
  if (inode_desc_it == fim_context.inode_map.end()) {
    VLOG(1) << "Missing inode number";
    syscall_context.partial = true;
    return true;
  }

  AuditdFimInodeDescriptor inode_desc = inode_desc_it->second;

  AuditdFimIOData data;
  data.target = inode_desc.path;
  data.type = (syscall_context.type == AuditdFimSyscallContext::Type::Read
               ? AuditdFimIOData::Type::Read : AuditdFimIOData::Type::Write);
  data.state_changed = state_changed;
  syscall_context.syscall_data = data;

  return true;
}

bool HandleDupSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  syscall_context.type = AuditdFimSyscallContext::Type::Dup;

  std::uint64_t fd;
  if (!GetIntegerFieldFromMap(fd, record.fields, "a0")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
            "file descriptor field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdMap &fd_map = *GetOrCreateProcessMap(fim_context, syscall_context.process_id, true);

  auto fd_desc_it = fd_map.find(fd);
  if (fd_desc_it == fd_map.end()) {
    VLOG(1) << "Untracked file descriptor";
    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdDescriptor fd_desc = fd_desc_it->second;
  fd_map[fd] = fd_desc;

  return true;
}

bool HandleCloseSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  syscall_context.type = AuditdFimSyscallContext::Type::Close;

  std::uint64_t fd;
  if (!GetIntegerFieldFromMap(fd, record.fields, "a0")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
            "file descriptor field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdMap &fd_map = *GetOrCreateProcessMap(fim_context, syscall_context.process_id, true);

  auto fd_desc_it = fd_map.find(fd);
  if (fd_desc_it == fd_map.end()) {
    VLOG(1) << "Untracked file descriptor";
    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdDescriptor fd_desc = fd_desc_it->second;
  fd_map.erase(fd_desc_it);

  auto inode_desc_it = fim_context.inode_map.find(fd_desc.inode);
  if (inode_desc_it == fim_context.inode_map.end()) {
    VLOG(1) << "Missing inode number";
    syscall_context.partial = true;
    return true;
  }

  AuditdFimInodeDescriptor inode_desc = inode_desc_it->second;

  AuditdFimIOData data;
  data.target = inode_desc.path;
  data.type = AuditdFimIOData::Type::Close;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  return true;
}

bool HandleUnlinkSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  syscall_context.type = AuditdFimSyscallContext::Type::Unlink;

  if (syscall_context.path_record_map.size() != 2) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
            "AUDIT_PATH records mismatch)";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimIOData data;
  data.target = NormalizePath(syscall_context.path_record_map[0].path, syscall_context.path_record_map[1].path);
  data.type = AuditdFimIOData::Type::Unlink;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  AuditdFimInodeDescriptor inode_desc;
  inode_desc.path = data.target;
  if (syscall_context.path_record_map[1].path.back() == '/') {
    inode_desc.type = AuditdFimInodeDescriptor::Type::Folder;
  } else {
    inode_desc.type = AuditdFimInodeDescriptor::Type::File;
  }

  fim_context.inode_map.erase(syscall_context.path_record_map[1].inode);

  return true;
}

bool HandleRenameSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  syscall_context.type = AuditdFimSyscallContext::Type::Rename;

  if (syscall_context.path_record_map.size() != 4) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
            "AUDIT_PATH records mismatch)";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimRenameData data;
  data.source = NormalizePath(syscall_context.path_record_map[0].path, syscall_context.path_record_map[2].path);
  data.destination = NormalizePath(syscall_context.path_record_map[1].path, syscall_context.path_record_map[3].path);
  syscall_context.syscall_data = data;

  AuditdFimInodeDescriptor inode_desc;
  inode_desc.path = data.destination;
  if (syscall_context.path_record_map[3].path.back() == '/') {
    inode_desc.type = AuditdFimInodeDescriptor::Type::Folder;
  } else {
    inode_desc.type = AuditdFimInodeDescriptor::Type::File;
  }

  fim_context.inode_map.erase(syscall_context.path_record_map[2].inode);
  fim_context.inode_map[syscall_context.path_record_map[3].inode] = inode_desc;

  return true;
}

bool HandleOpenOrCreateSyscallRecord(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  /// \todo truncate?
  syscall_context.type = AuditdFimSyscallContext::Type::Open;

  AuditdFimFdMap &fd_map = *GetOrCreateProcessMap(fim_context, syscall_context.process_id, true);

  if (syscall_context.path_record_map.size() != 1) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
            "AUDIT_PATH records mismatch)";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimIOData data;
  data.target = NormalizePath(syscall_context.cwd, syscall_context.path_record_map[0].path);
  data.type = AuditdFimIOData::Type::Open;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  AuditdFimFdDescriptor fd_desc;
  fd_desc.inode = syscall_context.path_record_map[0].inode;
  fd_desc.last_operation = AuditdFimFdDescriptor::OperationType::Open;
  fd_map[syscall_context.return_value] = fd_desc;

  AuditdFimInodeDescriptor inode_desc;
  inode_desc.path = data.target;
  if (syscall_context.path_record_map[0].path.back() == '/') {
    inode_desc.type = AuditdFimInodeDescriptor::Type::Folder;
  } else {
    inode_desc.type = AuditdFimInodeDescriptor::Type::File;
  }

  fim_context.inode_map[fd_desc.inode] = inode_desc;
  return true;
}

bool AuditSyscallRecordHandler(AuditdFimContext &fim_context, AuditdFimSyscallContext &syscall_context, const AuditEventRecord &record) noexcept {
  if (!GetIntegerFieldFromMap(syscall_context.return_value, record.fields, "exit", 0)) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
            "exit field is either missing or not valid.";

    syscall_context.partial = true;
  }

  if (!GetStringFieldFromMap(syscall_context.executable_path, record.fields, "exe")) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
            "process id field is either missing or not valid.";

    syscall_context.partial = true;
  }

  switch (syscall_context.syscall_number) {
    case __NR_link:
    case __NR_linkat:
    case __NR_symlink:
    case __NR_symlinkat: {
      if (syscall_context.syscall_number == __NR_link || syscall_context.syscall_number == __NR_linkat) {
        syscall_context.type = AuditdFimSyscallContext::Type::Link;
      } else {
        syscall_context.type = AuditdFimSyscallContext::Type::Symlink;
      }

      return false;
    }
    case __NR_name_to_handle_at: {
      syscall_context.type = AuditdFimSyscallContext::Type::NameToHandleAt;
      return false;
    }

    case __NR_mmap:
    case __NR_mremap:
    case __NR_munmap:
    case __NR_remap_file_pages: {
      syscall_context.type = AuditdFimSyscallContext::Type::Mmap;
      return false;
    }

    case __NR_open_by_handle_at: {
      syscall_context.type = AuditdFimSyscallContext::Type::Open;
      AuditdFimFdMap &fd_map = *GetOrCreateProcessMap(fim_context, syscall_context.process_id, true);
      return false;
    }

    case __NR_rename:
    case __NR_renameat:
    case __NR_renameat2: {
      return HandleRenameSyscallRecord(fim_context, syscall_context, record);
    }

    case __NR_unlink:
    case __NR_unlinkat: {
      return HandleUnlinkSyscallRecord(fim_context, syscall_context, record);
    }

    case __NR_creat:
    case __NR_mknod:
    case __NR_mknodat:
    case __NR_open:
    case __NR_openat: {
      return HandleOpenOrCreateSyscallRecord(fim_context, syscall_context, record);
    }

    case __NR_close: {
      return HandleCloseSyscallRecord(fim_context, syscall_context, record);
    }

    case __NR_dup:
    case __NR_dup2:
    case __NR_dup3: {
      return HandleDupSyscallRecord(fim_context, syscall_context, record);
    }

    case __NR_pread64:
    case __NR_preadv:
    case __NR_read:
    case __NR_readv:
    case __NR_write:
    case __NR_writev:
    case __NR_pwrite64:
    case __NR_pwritev: {
      return HandleReadOrWriteSyscallRecord(fim_context, syscall_context, record);
    }

    default: {
      return false;
    }
  }
}
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

      context_.configuration.included_path_list.reserve(
          context_.configuration.included_path_list.size() + solved_path_list.size());
      context_.configuration.included_path_list.insert(
          context_.configuration.included_path_list.end(),
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

      context_.configuration.excluded_path_list.resize(
          context_.configuration.excluded_path_list.size() +
          context_.configuration.excluded_path_list.size());
      context_.configuration.excluded_path_list.insert(
          context_.configuration.excluded_path_list.end(),
          solved_path_list.begin(),
          solved_path_list.end());
    }
  }

  if (root_key.find("show_accesses") != root_key.not_found()) {
    auto key = root_key.get_child("show_accesses");
    auto value = key.get_value<std::string>();

    context_.configuration.show_accesses = (value == "true");
  }
}

Status AuditdFimEventSubscriber::Callback(const ECRef& event_context,
                                          const SCRef& subscription_context) {
  std::vector<Row> emitted_row_list;
  auto exit_status = ProcessEvents(emitted_row_list, context_, event_context->audit_events);
  for (Row &row : emitted_row_list) {
    add(row);
  }

  return exit_status;
}

Status AuditdFimEventSubscriber::ProcessEvents(
    std::vector<Row> &emitted_row_list,
    AuditdFimContext &fim_context,
    const std::vector<AuditEvent>& event_list) noexcept {

  emitted_row_list.clear();

  auto L_ShouldHandle = [](std::uint64_t syscall_number) -> bool {
      const auto &syscall_set = AuditdFimEventSubscriber::GetSyscallSet();
    return (syscall_set.find(static_cast<int>(syscall_number)) != syscall_set.end());
  };

  // Configuration helpers
  auto L_isPathIncluded = [&fim_context](const std::string& path) -> bool {
    return (std::find(fim_context.configuration.included_path_list.begin(),
                      fim_context.configuration.included_path_list.end(),
                      path) != fim_context.configuration.included_path_list.end());
  };

  auto L_isPathExcluded = [&fim_context](const std::string& path) -> bool {
    return (std::find(fim_context.configuration.excluded_path_list.begin(),
                      fim_context.configuration.excluded_path_list.end(),
                      path) != fim_context.configuration.excluded_path_list.end());
  };

  auto osquery_pid = getpid();

  for (const auto &event : event_list) {
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    const auto &event_data = boost::get<SyscallAuditEventData>(event.data);
      if (event_data.process_id == osquery_pid || event_data.parent_process_id == osquery_pid) {
      continue;
    }

    if (!L_ShouldHandle(event_data.syscall_number)) {
      continue;
    }

    AuditdFimSyscallContext syscall_context = {};
    syscall_context.syscall_number = event_data.syscall_number;
    syscall_context.process_id = event_data.process_id;
    syscall_context.parent_process_id = event_data.parent_process_id;

    const AuditEventRecord *syscall_record = nullptr;
    bool record_error = false;

    for (const auto &record : event.record_list) {
      switch (record.type) {
      case AUDIT_SYSCALL: {
        syscall_record = &record;
        break;
      }

      case AUDIT_CWD: {
        if (!ParseAuditCwdRecord(syscall_context.cwd, record)) {
          record_error = true;
          break;
        }
        break;
      }

      case AUDIT_PATH: {
        AuditdFimPathRecordItem output;
        if (!ParseAuditPathRecord(output, record)) {
          record_error = true;
          break;
        }

        syscall_context.path_record_map[output.index] = output;
        break;
      }

      case AUDIT_MMAP: {
        if (!ParseAuditMmapRecord(record)) {
          record_error = true;
          break;
        }
        break;
      }

      default:
        break;
      }

      if (record_error) {
        break;
      }
    }

    // Update the inode map; this is a catch-all, and may be partially
    // reverted by the syscall handler (i.e.: unlink will erase an entry)
    for (const auto &p : syscall_context.path_record_map) {
      const AuditdFimPathRecordItem &path_item = p.second;

      AuditdFimInodeDescriptor inode_descriptor;
      inode_descriptor.path = path_item.path;
      if (path_item.path.back() == '/') {
        inode_descriptor.type = AuditdFimInodeDescriptor::Type::Folder;
      } else {
        inode_descriptor.type = AuditdFimInodeDescriptor::Type::File;
      }

      fim_context.inode_map[path_item.inode] = inode_descriptor;
    }

    if (record_error || syscall_record == nullptr) {
      VLOG(1) << "Invalid syscall event; one or more child records were malformed";
      continue;
    }

    if (!AuditSyscallRecordHandler(fim_context, syscall_context, *syscall_record)) {
      VLOG(1) << "Invalid syscall event; the AUDIT_SYSCALL record was malformed";
      continue;
    }

    if (syscall_context.process_id == getpid() || syscall_context.parent_process_id == getpid()) {
      continue;
    }

    if (FLAGS_audit_fim_debug) {
      std::cout << syscall_context << std::endl;
    }

    Row row;
    if (EmitRowFromSyscallContext(row, syscall_context)) {
      emitted_row_list.push_back(row);
    }
  }

  /*
    If we have lost audit event records (i.e.: the kernel queue is smaller
    than the system activity) we may end up having orphaned process entries.

    Erase the objects that no longer have a valid process id
  */

  for (auto it = fim_context.process_map.begin(); it != fim_context.process_map.end();) {
    errno = 0;
    if (getpgid(it->first) != static_cast<__pid_t>(-1)) {
      it++;
    } else if (errno == ESRCH) {
      it = fim_context.process_map.erase(it);
    }
  }

  return Status(0, "OK");
}

const std::set<int> &AuditdFimEventSubscriber::GetSyscallSet() noexcept {
  static const std::set<int> syscall_set = {__NR_link, __NR_linkat, __NR_symlink, __NR_symlinkat, __NR_unlink, __NR_unlinkat, __NR_rename, __NR_renameat, __NR_renameat2, __NR_mknod, __NR_mknodat, __NR_open, __NR_openat, __NR_open_by_handle_at, __NR_name_to_handle_at, __NR_close, __NR_dup, __NR_dup2, __NR_dup3, __NR_pread64, __NR_preadv, __NR_read, __NR_readv, __NR_mmap, __NR_mremap, __NR_munmap, __NR_remap_file_pages, __NR_write, __NR_writev, __NR_pwrite64, __NR_pwritev };
  return syscall_set;
}
}
