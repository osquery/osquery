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

#include <cstdint>
#include <iostream>

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
     audit_show_partial_fim_events,
     false,
     "Allow the audit publisher to show partial file events");

FLAG(bool,
     audit_show_untracked_res_warnings,
     false,
     "Shows warnings about untracked processes (started before osquery)");

HIDDEN_FLAG(bool,
            audit_fim_debug,
            false,
            "Show debug messages for the FIM table");

REGISTER(AuditdFimEventSubscriber, "event_subscriber", "auditd_fim_events");

namespace {
std::ostream& operator<<(std::ostream& stream,
                         AuditdFimSyscallContext::Type type) {
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

std::ostream& operator<<(std::ostream& stream,
                         const AuditdFimSyscallContext& syscall_context) {
  stream << "Type: " << syscall_context.type
         << " ProcessID: " << syscall_context.process_id
         << " ImagePath: " << syscall_context.executable_path << " Data: ";

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
    const auto& data =
        boost::get<AuditdFimSrcDestData>(syscall_context.syscall_data);
    stream << data.source << " -> " << data.destination;
    break;
  }

  case AuditdFimSyscallContext::Type::Unlink:
  case AuditdFimSyscallContext::Type::Read:
  case AuditdFimSyscallContext::Type::Write:
  case AuditdFimSyscallContext::Type::Open:
  case AuditdFimSyscallContext::Type::Close: {
    const auto& data =
        boost::get<AuditdFimIOData>(syscall_context.syscall_data);
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

    stream << data.target
           << " StateChange: " << (data.state_changed ? "True" : "False")
           << " ";
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

  case AuditdFimSyscallContext::Type::CloneOrFork: {
    stream << "CloneOrFork";
    break;
  }

  case AuditdFimSyscallContext::Type::Execve: {
    stream << "Execve";
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

bool EmitRowFromSyscallContext(
    Row& row,
    const AuditdFimContext& fim_context,
    const AuditdFimSyscallContext& syscall_context) noexcept {
  auto L_IsPathIncluded = [&fim_context](const std::string& path) -> bool {
    if (std::find(fim_context.configuration.excluded_path_list.begin(),
                  fim_context.configuration.excluded_path_list.end(),
                  path) != fim_context.configuration.excluded_path_list.end()) {
      return false;
    }

    return (std::find(fim_context.configuration.included_path_list.begin(),
                      fim_context.configuration.included_path_list.end(),
                      path) !=
            fim_context.configuration.included_path_list.end());
  };

  row.clear();
  bool is_write_operation = false;

  if (!FLAGS_audit_show_partial_fim_events && syscall_context.partial) {
    return false;
  }

  switch (syscall_context.type) {
  case AuditdFimSyscallContext::Type::Symlink:
  case AuditdFimSyscallContext::Type::Rename:
  case AuditdFimSyscallContext::Type::Link: {
    if (syscall_context.type == AuditdFimSyscallContext::Type::Symlink) {
      row["operation"] = "symlink";
    } else if (syscall_context.type == AuditdFimSyscallContext::Type::Rename) {
      row["operation"] = "rename";
    } else {
      row["operation"] = "link";
    }

    const auto& data =
        boost::get<AuditdFimSrcDestData>(syscall_context.syscall_data);

    row["path1"] = data.source;
    row["path2"] = data.destination;

    is_write_operation = true;
    break;
  }

  case AuditdFimSyscallContext::Type::Unlink:
  case AuditdFimSyscallContext::Type::Read:
  case AuditdFimSyscallContext::Type::Write:
  case AuditdFimSyscallContext::Type::Open:
  case AuditdFimSyscallContext::Type::Close:
  case AuditdFimSyscallContext::Type::Truncate:
  case AuditdFimSyscallContext::Type::Mmap: {
    const auto& data =
        boost::get<AuditdFimIOData>(syscall_context.syscall_data);

    if (!data.state_changed) {
      return false;
    }

    if (data.type == AuditdFimIOData::Type::Open) {
      row["operation"] = "open";

    } else if (data.type == AuditdFimIOData::Type::Read) {
      row["operation"] = "read";

    } else if (data.type == AuditdFimIOData::Type::Write) {
      row["operation"] = "write";
      is_write_operation = true;

    } else if (data.type == AuditdFimIOData::Type::Unlink) {
      row["operation"] = "unlink";
      is_write_operation = true;

    } else {
      row["operation"] = "close";
    }

    row["path1"] = data.target;
    break;
  }

  case AuditdFimSyscallContext::Type::Dup:
  case AuditdFimSyscallContext::Type::NameToHandleAt:
  case AuditdFimSyscallContext::Type::CloneOrFork:
  case AuditdFimSyscallContext::Type::Execve: {
    return false;
  }
  }

  // Filter the events
  bool include_event = L_IsPathIncluded(row["path1"]);
  if (!include_event && row.find("path2") != row.end()) {
    include_event = L_IsPathIncluded(row["path2"]);
  }

  if (!include_event) {
    return false;
  }

  if (!fim_context.configuration.show_accesses && !is_write_operation) {
    return false;
  }

  row["pid"] =
      std::to_string(static_cast<std::uint64_t>(syscall_context.process_id));

  row["ppid"] = std::to_string(
      static_cast<std::uint64_t>(syscall_context.parent_process_id));

  row["executable"] = syscall_context.executable_path;
  row["partial"] = (syscall_context.partial ? "true" : "false");
  row["cwd"] = syscall_context.cwd;
  row["uptime"] = std::to_string(tables::getUptime());

  return true;
}

bool ParseAuditCwdRecord(std::string& cwd,
                         const AuditEventRecord& record) noexcept {
  return GetStringFieldFromMap(cwd, record.fields, "cwd");
}

bool ParseAuditMmapRecord(AuditdFimSyscallContext& syscall_context,
                          const AuditEventRecord& record) noexcept {
  syscall_context.mmap_record_present = true;

  if (!GetIntegerFieldFromMap(
          syscall_context.mmap_file_descriptor, record.fields, "fd", 16)) {
    return false;
  }

  GetIntegerFieldFromMap(
      syscall_context.mmap_prot_flags, record.fields, "flags", 16, PROT_WRITE);
  return true;
}

bool ParseAuditPathRecord(AuditdFimPathRecordItem& output,
                          const AuditEventRecord& record) noexcept {
  std::uint64_t item_index;
  if (!GetIntegerFieldFromMap(item_index, record.fields, "item", 10))
    return false;

  // The inode number is not mandatory when dealing with folders
  std::uint64_t inode;
  GetIntegerFieldFromMap(inode, record.fields, "inode", 10, 0);

  // The 'name' field is sometimes left blank (i.e.: open_by_handle_at)
  GetStringFieldFromMap(output.path, record.fields, "name");

  output.index = static_cast<std::size_t>(item_index);
  output.inode = static_cast<ino_t>(inode);

  return true;
}

bool HandleFileDescriptorSyscallRecord(
    AuditdFimContext& fim_context,
    AuditdFimSyscallContext& syscall_context,
    const AuditEventRecord& record) noexcept {
  // Set the syscall context type and determine if this is a
  // read or write operation
  bool write_operation = false;

  switch (syscall_context.syscall_number) {
  case __NR_pread64:
  case __NR_preadv:
  case __NR_read:
  case __NR_readv: {
    write_operation = false;
    syscall_context.type = AuditdFimSyscallContext::Type::Read;
    break;
  }

  case __NR_pwrite64:
  case __NR_pwritev:
  case __NR_write:
  case __NR_writev: {
    write_operation = true;
    syscall_context.type = AuditdFimSyscallContext::Type::Write;
    break;
  }

  case __NR_ftruncate: {
    write_operation = true;
    syscall_context.type = AuditdFimSyscallContext::Type::Truncate;
    break;
  }

  case __NR_mmap: {
    write_operation = ((syscall_context.mmap_prot_flags & PROT_WRITE) != 0);
    syscall_context.type = AuditdFimSyscallContext::Type::Mmap;
    break;
  }
  }

  // Get the file descriptor. Mmap syscalls store them into a dedicated
  // event record of type AUDIT_MMAP
  std::uint64_t fd;
  if (syscall_context.syscall_number == __NR_mmap) {
    fd = syscall_context.mmap_file_descriptor;

  } else {
    if (!GetIntegerFieldFromMap(fd, record.fields, "a0", 16)) {
      VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
                 "file descriptor field is either missing or not valid.";

      syscall_context.partial = true;
      return false;
    }
  }

  // Only track state changes
  AuditdFimFdDescriptor* fd_desc;
  if (!fim_context.process_map.getReference(
          fd_desc, syscall_context.process_id, fd)) {
    syscall_context.partial = true;
    return false;
  }

  bool state_changed = false;

  switch (fd_desc->last_operation) {
  case AuditdFimFdDescriptor::OperationType::Open: {
    if (write_operation) {
      fd_desc->last_operation = AuditdFimFdDescriptor::OperationType::Write;
    } else {
      fd_desc->last_operation = AuditdFimFdDescriptor::OperationType::Read;
    }

    state_changed = true;
    break;
  }

  case AuditdFimFdDescriptor::OperationType::Read: {
    if (write_operation) {
      fd_desc->last_operation = AuditdFimFdDescriptor::OperationType::Write;
      state_changed = true;
    }

    break;
  }

  case AuditdFimFdDescriptor::OperationType::Write: {
    break;
  }
  }

  // Update the state map
  AuditdFimInodeDescriptor* ino_desc;
  if (!fim_context.inode_map.getReference(ino_desc, fd_desc->inode)) {
    syscall_context.partial = true;
    return true;
  }

  AuditdFimIOData data;
  data.target = ino_desc->path;
  data.type = (write_operation ? AuditdFimIOData::Type::Write
                               : AuditdFimIOData::Type::Read);
  data.state_changed = state_changed;
  syscall_context.syscall_data = data;

  return true;
}

bool HandleDupSyscallRecord(AuditdFimContext& fim_context,
                            AuditdFimSyscallContext& syscall_context,
                            const AuditEventRecord& record) noexcept {
  // The dup/dup2/dup3 syscalls are all the same for us; the file
  // descriptor is always the first (a0) parameter.

  syscall_context.type = AuditdFimSyscallContext::Type::Dup;

  std::uint64_t fd;
  if (!GetIntegerFieldFromMap(fd, record.fields, "a0", 16)) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
               "file descriptor field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  if (!fim_context.process_map.duplicate(
          syscall_context.process_id, fd, syscall_context.return_value)) {
    syscall_context.partial = true;
    return false;
  }

  return true;
}

bool HandleCloseSyscallRecord(AuditdFimContext& fim_context,
                              AuditdFimSyscallContext& syscall_context,
                              const AuditEventRecord& record) noexcept {
  // The input file descriptor is in the first (a0) parameter of the
  // AUDIT_SYSCALL record

  syscall_context.type = AuditdFimSyscallContext::Type::Close;

  std::uint64_t fd;
  if (!GetIntegerFieldFromMap(fd, record.fields, "a0", 16)) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
               "file descriptor field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  AuditdFimFdDescriptor fd_desc;
  if (!fim_context.process_map.takeAndRemove(
          fd_desc, syscall_context.process_id, fd)) {
    syscall_context.partial = true;
    return false;
  }

  AuditdFimInodeDescriptor* ino_desc;
  if (!fim_context.inode_map.getReference(ino_desc, fd_desc.inode)) {
    syscall_context.partial = true;
    return true;
  }

  AuditdFimIOData data;
  data.target = ino_desc->path;
  data.type = AuditdFimIOData::Type::Close;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  return true;
}

bool HandleUnlinkSyscallRecord(AuditdFimContext& fim_context,
                               AuditdFimSyscallContext& syscall_context,
                               const AuditEventRecord& record) noexcept {
  // The unlink and unlinkat syscalls receive two AUDIT_PATH records; the
  // first one is the working directory, while the second one is the file
  // path. Note that the second path can either be relative or absolute.

  syscall_context.type = AuditdFimSyscallContext::Type::Unlink;

  if (syscall_context.path_record_map.size() != 2) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  AuditdFimIOData data;
  data.target = NormalizePath(syscall_context.path_record_map[0].path,
                              syscall_context.path_record_map[1].path);

  data.type = AuditdFimIOData::Type::Unlink;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  fim_context.inode_map.remove(syscall_context.path_record_map[1].inode);
  return true;
}

bool HandleRenameSyscallRecord(AuditdFimContext& fim_context,
                               AuditdFimSyscallContext& syscall_context,
                               const AuditEventRecord& record) noexcept {
  // The rename/renameat/renameat2 syscalls all receive either four
  // or give AUDIT_PATH records
  //
  // item 0: working directory of the first path
  // item 1: working directory of the second path
  // item 2: source file name
  // item 3: destination file name
  //
  // If the destination file is being overwritten:
  //
  // item 0: working directory of the first path
  // item 1: working directory of the second path
  // item 2: source file name
  // item 3: file being overwritten
  // item 4: destination file name
  //
  // In this case the items 3 and 4 have the same path but
  // different inodes
  syscall_context.type = AuditdFimSyscallContext::Type::Rename;

  AuditdFimPathRecordItem source_cwd;
  AuditdFimPathRecordItem source_path;

  AuditdFimPathRecordItem destination_cwd;
  AuditdFimPathRecordItem destination_path;

  if (syscall_context.path_record_map.size() == 4) {
    source_cwd = syscall_context.path_record_map[0];
    destination_cwd = syscall_context.path_record_map[1];

    source_path = syscall_context.path_record_map[2];
    destination_path = syscall_context.path_record_map[3];

  } else if (syscall_context.path_record_map.size() == 5) {
    source_cwd = syscall_context.path_record_map[0];
    destination_cwd = syscall_context.path_record_map[1];

    source_path = syscall_context.path_record_map[2];
    destination_path = syscall_context.path_record_map[4];
  } else {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  AuditdFimSrcDestData data;
  data.source = NormalizePath(source_cwd.path, source_path.path);
  data.destination = NormalizePath(destination_cwd.path, destination_path.path);

  syscall_context.syscall_data = data;

  AuditdFimInodeDescriptor ino_desc;
  if (!fim_context.inode_map.takeAndRemove(
          ino_desc, syscall_context.path_record_map[2].inode)) {
    syscall_context.partial = true;
    return false;
  }

  fim_context.inode_map.save(
      syscall_context.path_record_map[3].inode, ino_desc.type, ino_desc.path);
  return true;
}

bool HandleOpenOrCreateSyscallRecord(AuditdFimContext& fim_context,
                                     AuditdFimSyscallContext& syscall_context,
                                     const AuditEventRecord& record) noexcept {
  // The open/openat/open_by_handle_at can also truncate the file
  // with the right flags. If this is the case, mark the file as
  // written.
  bool is_truncate = false;

  if (syscall_context.syscall_number == __NR_open) {
    std::uint64_t open_flags;
    GetIntegerFieldFromMap(open_flags,
                           record.fields,
                           "a1",
                           16,
                           static_cast<std::uint64_t>(O_TRUNC));
    is_truncate = ((open_flags & O_TRUNC) != 0);

  } else if (syscall_context.syscall_number == __NR_openat ||
             syscall_context.syscall_number == __NR_open_by_handle_at) {
    std::uint64_t open_flags;
    GetIntegerFieldFromMap(open_flags,
                           record.fields,
                           "a2",
                           16,
                           static_cast<std::uint64_t>(O_TRUNC));
    is_truncate = ((open_flags & O_TRUNC) != 0);

  } else {
    syscall_context.type = AuditdFimSyscallContext::Type::Open;
  }

  if (is_truncate) {
    syscall_context.type = AuditdFimSyscallContext::Type::Write;
  } else {
    syscall_context.type = AuditdFimSyscallContext::Type::Open;
  }

  /*
    Paths are passed via AUDIT_PATH records; this is a quick recap
    of how they work for each system call.

    Sample record
      audit(1502573850.697:38396): item=0 name="/etc/ld.so.cache"
        inode=67842177 dev=fd:00 mode=0100644 ouid=0 ogid=0
        rdev=00:00 obj=unconfined_u:object_r:ld_so_cache_t:s0
        objtype=NORMAL

    The item id must be used to determine what we are reading. When
    the working directory is missing, we can use the one in AUDIT_CWD.

    creat():
    mknod():
    mknodat():
      item 0: Working directory (path + inode)
      item 1: File (relative path + inode)

    open_by_handle_at():
    openat():
      item 0: File (inode)

    open():
      Can have one, two or three AUDIT_PATH records.
      In case it has three, use the one at index 0.
  */

  bool wrong_record_count = false;
  std::string input_path_working_dir;
  std::string raw_input_path;
  ino_t input_inode;
  std::string normalized_path;

  switch (syscall_context.syscall_number) {
  case __NR_creat:
  case __NR_mknod:
  case __NR_mknodat: {
    if (syscall_context.path_record_map.size() != 2) {
      wrong_record_count = true;
      break;
    }

    input_path_working_dir = syscall_context.path_record_map[0].path;
    raw_input_path = syscall_context.path_record_map[1].path;
    input_inode = syscall_context.path_record_map[1].inode;
    normalized_path = NormalizePath(input_path_working_dir, raw_input_path);

    break;
  }

  case __NR_openat:
  case __NR_open: {
    if (syscall_context.path_record_map.size() == 1) {
      input_path_working_dir = syscall_context.cwd;
      raw_input_path = syscall_context.path_record_map[0].path;
      input_inode = syscall_context.path_record_map[0].inode;

    } else if (syscall_context.path_record_map.size() == 2) {
      input_path_working_dir = syscall_context.path_record_map[0].path;
      raw_input_path = syscall_context.path_record_map[1].path;
      input_inode = syscall_context.path_record_map[1].inode;

    } else if (syscall_context.path_record_map.size() == 3) {
      input_path_working_dir = syscall_context.cwd;
      raw_input_path = syscall_context.path_record_map[0].path;
      input_inode = syscall_context.path_record_map[0].inode;

    } else {
      wrong_record_count = true;
      break;
    }

    normalized_path = NormalizePath(input_path_working_dir, raw_input_path);
    break;
  }

  case __NR_open_by_handle_at: {
    if (syscall_context.path_record_map.size() != 1) {
      wrong_record_count = true;
      break;
    }

    input_path_working_dir = syscall_context.cwd;
    input_inode = syscall_context.path_record_map[0].inode;

    AuditdFimInodeDescriptor* ino_desc;
    if (!fim_context.inode_map.getReference(ino_desc, input_inode)) {
      syscall_context.partial = true;
      return false;
    }

    raw_input_path = syscall_context.path_record_map[0].path;
    normalized_path = NormalizePath(input_path_working_dir, raw_input_path);

    break;
  }
  }

  if (wrong_record_count) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  AuditdFimIOData data;
  data.target = normalized_path;
  data.type = AuditdFimIOData::Type::Open;
  data.state_changed = true;
  syscall_context.syscall_data = data;

  // If the file has been truncated (O_TRUNC flag), mark as written
  AuditdFimFdDescriptor::OperationType last_operation;
  if (is_truncate) {
    last_operation = AuditdFimFdDescriptor::OperationType::Write;
  } else {
    last_operation = AuditdFimFdDescriptor::OperationType::Open;
  }

  fim_context.process_map.save(syscall_context.return_value,
                               syscall_context.process_id,
                               input_inode,
                               last_operation);
  fim_context.inode_map.save(
      input_inode, AuditdFimInodeDescriptor::Type::File, data.target);

  return true;
}

bool HandleLinkAndSymlinkSyscallRecord(
    AuditdFimContext& fim_context,
    AuditdFimSyscallContext& syscall_context,
    const AuditEventRecord& record) noexcept {
  if (syscall_context.syscall_number == __NR_symlink ||
      syscall_context.syscall_number == __NR_symlinkat) {
    syscall_context.type = AuditdFimSyscallContext::Type::Symlink;
  } else {
    syscall_context.type = AuditdFimSyscallContext::Type::Link;
  }

  /*
    This syscall receives three AUDIT_PATH records:

    item0: oldpath
    item1: working directory for newpath
    item2: newpath

    Since we only have 3 records, path 0 must be normalized with
    the cwd parameter of the AUDIT_CWD record.
  */

  if (syscall_context.path_record_map.size() != 3) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  AuditdFimSrcDestData data;
  data.source = NormalizePath(syscall_context.cwd,
                              syscall_context.path_record_map[0].path);

  data.destination = NormalizePath(syscall_context.path_record_map[1].path,
                                   syscall_context.path_record_map[2].path);

  syscall_context.syscall_data = data;

  // If this is a link/linkat syscall, we can copy the inode number from
  // the AUDIT_PATH record containing the newpath parameter
  AuditdFimInodeDescriptor::Type source_type;
  AuditdFimInodeDescriptor::Type destination_type =
      AuditdFimInodeDescriptor::Type::File;

  auto source_path = syscall_context.path_record_map[0];
  if (syscall_context.syscall_number == __NR_link ||
      syscall_context.syscall_number == __NR_linkat) {
    source_type = AuditdFimInodeDescriptor::Type::File;
    source_path.inode = syscall_context.path_record_map[2].inode;

  } else {
    if (syscall_context.path_record_map[0].path.back() == '/') {
      source_type = AuditdFimInodeDescriptor::Type::Folder;
    } else {
      source_type = AuditdFimInodeDescriptor::Type::File;
    }
  }

  fim_context.inode_map.save(source_path.inode, source_type, data.source);
  fim_context.inode_map.save(syscall_context.path_record_map[2].inode,
                             destination_type,
                             data.destination);

  return true;
}

bool HandleNameToHandleAtSyscallRecord(
    AuditdFimContext& fim_context,
    AuditdFimSyscallContext& syscall_context,
    const AuditEventRecord& record) noexcept {
  // This syscall prepares a file_handle structure that can be later
  // used to open the file without solving the path from scratch.
  //
  // We have to handle this syscall because it receives both the inode
  // and path name for the file to open (the open_by_handle_at receives
  // no path information).
  syscall_context.type = AuditdFimSyscallContext::Type::NameToHandleAt;

  // This syscall only receives the file path; we have to use the
  // AUDIT_CWD record to normalize it
  if (syscall_context.path_record_map.size() != 1) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  std::string normalized_path = NormalizePath(
      syscall_context.cwd, syscall_context.path_record_map[0].path);

  AuditdFimInodeDescriptor::Type type;
  if (syscall_context.path_record_map[0].path.back() == '/') {
    type = AuditdFimInodeDescriptor::Type::Folder;
  } else {
    type = AuditdFimInodeDescriptor::Type::File;
  }

  fim_context.inode_map.save(
      syscall_context.path_record_map[0].inode, type, normalized_path);
  return true;
}

bool HandleTruncateSyscallRecord(AuditdFimContext& fim_context,
                                 AuditdFimSyscallContext& syscall_context,
                                 const AuditEventRecord& record) noexcept {
  // This is the truncate(path, size) syscall; it only receives one AUDIT_PATH
  // record, so we have to solve the path using the AUDIT_CWD information.
  syscall_context.type = AuditdFimSyscallContext::Type::Truncate;

  if (syscall_context.path_record_map.size() != 1) {
    VLOG(1) << "Malformed AUDIT_SYSCALL event received ("
               "AUDIT_PATH records mismatch) in syscall "
            << syscall_context.syscall_number;

    for (const auto& p : syscall_context.path_record_map) {
      VLOG(1) << p.second.index << " " << p.second.path;
    }

    syscall_context.partial = true;
    return false;
  }

  AuditdFimIOData data;
  data.state_changed = true;
  data.type = AuditdFimIOData::Type::Write;

  data.target = NormalizePath(syscall_context.cwd,
                              syscall_context.path_record_map[0].path);

  syscall_context.syscall_data = data;

  fim_context.inode_map.save(syscall_context.path_record_map[0].inode,
                             AuditdFimInodeDescriptor::Type::File,
                             data.target);
  return true;
}

bool AuditSyscallRecordHandler(AuditdFimContext& fim_context,
                               AuditdFimSyscallContext& syscall_context,
                               const AuditEventRecord& record,
                               bool& skip_row_emission) noexcept {
  skip_row_emission = false;

  if (!GetIntegerFieldFromMap(
          syscall_context.return_value, record.fields, "exit", 16, 0U)) {
    VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
               "exit field is either missing or not valid.";

    syscall_context.partial = true;
    return false;
  }

  switch (syscall_context.syscall_number) {
  // The following syscalls are only handled to duplicate and/or create the fd
  // map
  case __NR_fork:
  case __NR_vfork:
  case __NR_clone: {
    skip_row_emission = true;
    syscall_context.type = AuditdFimSyscallContext::Type::CloneOrFork;

    return fim_context.process_map.clone(
        syscall_context.process_id,
        static_cast<pid_t>(syscall_context.return_value));
  }

  case __NR_execve: {
    skip_row_emission = true;
    syscall_context.type = AuditdFimSyscallContext::Type::Execve;

    fim_context.process_map.create(syscall_context.process_id);
    return true;
  }

  case __NR_link:
  case __NR_linkat:
  case __NR_symlink:
  case __NR_symlinkat: {
    return HandleLinkAndSymlinkSyscallRecord(
        fim_context, syscall_context, record);
  }

  case __NR_name_to_handle_at: {
    skip_row_emission = true;

    return HandleNameToHandleAtSyscallRecord(
        fim_context, syscall_context, record);
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
  case __NR_openat:
  case __NR_open_by_handle_at: {
    return HandleOpenOrCreateSyscallRecord(
        fim_context, syscall_context, record);
  }

  case __NR_close: {
    return HandleCloseSyscallRecord(fim_context, syscall_context, record);
  }

  case __NR_dup:
  case __NR_dup2:
  case __NR_dup3: {
    skip_row_emission = true;
    return HandleDupSyscallRecord(fim_context, syscall_context, record);
  }

  case __NR_truncate: {
    return HandleTruncateSyscallRecord(fim_context, syscall_context, record);
  }

  case __NR_pread64:
  case __NR_preadv:
  case __NR_read:
  case __NR_readv:
  case __NR_write:
  case __NR_writev:
  case __NR_pwrite64:
  case __NR_pwritev:
  case __NR_ftruncate: {
    return HandleFileDescriptorSyscallRecord(
        fim_context, syscall_context, record);
  }

  case __NR_mmap: {
    if (syscall_context.mmap_record_present) {
      return false;
    }

    return HandleFileDescriptorSyscallRecord(
        fim_context, syscall_context, record);
  }

  default: { return false; }
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
          context_.configuration.included_path_list.size() +
          solved_path_list.size());
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
  auto exit_status =
      ProcessEvents(emitted_row_list, context_, event_context->audit_events);
  for (Row& row : emitted_row_list) {
    add(row);
  }

  return exit_status;
}

Status AuditdFimEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    AuditdFimContext& fim_context,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();

  auto L_ShouldHandle = [](std::uint64_t syscall_number) -> bool {
    const auto& syscall_set = AuditdFimEventSubscriber::GetSyscallSet();
    return (syscall_set.find(static_cast<int>(syscall_number)) !=
            syscall_set.end());
  };

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
    if (!L_ShouldHandle(event_data.syscall_number)) {
      continue;
    }

    AuditdFimSyscallContext syscall_context = {};
    syscall_context.syscall_number = event_data.syscall_number;
    syscall_context.process_id = event_data.process_id;
    syscall_context.parent_process_id = event_data.parent_process_id;
    syscall_context.executable_path = event_data.executable_path;

    const AuditEventRecord* syscall_record = nullptr;
    bool record_error = false;

    for (const auto& record : event.record_list) {
      switch (record.type) {
      case AUDIT_SYSCALL: {
        syscall_record = &record;
        break;
      }

      case AUDIT_CWD: {
        if (!ParseAuditCwdRecord(syscall_context.cwd, record)) {
          VLOG(1) << "Invalid AUDIT_CWD record";
          record_error = true;
          break;
        }
        break;
      }

      case AUDIT_PATH: {
        AuditdFimPathRecordItem output;
        if (!ParseAuditPathRecord(output, record)) {
          VLOG(1) << "Invalid AUDIT_PATH record";
          record_error = true;
          break;
        }

        syscall_context.path_record_map[output.index] = output;
        break;
      }

      case AUDIT_MMAP: {
        if (!ParseAuditMmapRecord(syscall_context, record)) {
          VLOG(1) << "Invalid AUDIT_MMAP record";
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

    if (syscall_record == nullptr) {
      VLOG(1) << "Malformed audit event; the syscall record was not found";
      continue;
    }

    if (record_error) {
      VLOG(1)
          << "Invalid syscall event; one or more child records were malformed";
      continue;
    }

    bool skip_row_emission;
    if (!AuditSyscallRecordHandler(
            fim_context, syscall_context, *syscall_record, skip_row_emission)) {
      continue;
    }

    if (FLAGS_audit_fim_debug) {
      std::cout << syscall_context << std::endl;
    }

    if (!skip_row_emission) {
      Row row;

      if (EmitRowFromSyscallContext(row, fim_context, syscall_context)) {
        emitted_row_list.push_back(row);
      }
    }
  }

  return Status(0, "OK");
}

const std::set<int>& AuditdFimEventSubscriber::GetSyscallSet() noexcept {
  static const std::set<int> syscall_set = {__NR_link,
                                            __NR_linkat,
                                            __NR_symlink,
                                            __NR_symlinkat,
                                            __NR_unlink,
                                            __NR_unlinkat,
                                            __NR_rename,
                                            __NR_renameat,
                                            __NR_renameat2,
                                            __NR_creat,
                                            __NR_mknod,
                                            __NR_mknodat,
                                            __NR_open,
                                            __NR_openat,
                                            __NR_open_by_handle_at,
                                            __NR_name_to_handle_at,
                                            __NR_close,
                                            __NR_dup,
                                            __NR_dup2,
                                            __NR_dup3,
                                            __NR_pread64,
                                            __NR_preadv,
                                            __NR_read,
                                            __NR_readv,
                                            __NR_mmap,
                                            __NR_write,
                                            __NR_writev,
                                            __NR_pwrite64,
                                            __NR_pwritev,
                                            __NR_truncate,
                                            __NR_ftruncate,
                                            __NR_clone,
                                            __NR_fork,
                                            __NR_vfork,
                                            __NR_execve};
  return syscall_set;
}

AuditdFimInodeMap::AuditdFimInodeMap() {
  save(STDIN_FILENO, AuditdFimInodeDescriptor::Type::File, "stdin");
  save(STDOUT_FILENO, AuditdFimInodeDescriptor::Type::File, "stdout");
  save(STDERR_FILENO, AuditdFimInodeDescriptor::Type::File, "stderr");
}

bool AuditdFimInodeMap::getReference(AuditdFimInodeDescriptor*& ino_desc,
                                     ino_t inode) {
  auto it = data_.find(inode);
  if (it == data_.end()) {
    return false;
  }

  ino_desc = &it->second;
  return true;
}

bool AuditdFimInodeMap::takeAndRemove(AuditdFimInodeDescriptor& ino_desc,
                                      ino_t inode) {
  auto it = data_.find(inode);
  if (it == data_.end()) {
    return false;
  }

  ino_desc = it->second;
  data_.erase(it);

  return true;
}

void AuditdFimInodeMap::save(ino_t inode,
                             AuditdFimInodeDescriptor::Type type,
                             const std::string& path) {
  AuditdFimInodeDescriptor ino_desc;
  ino_desc.type = type;
  ino_desc.path = path;

  data_[inode] = ino_desc;

  if (data_.size() > 20000) {
    data_.erase(data_.begin());
  }
}

void AuditdFimInodeMap::remove(ino_t inode) {
  data_.erase(inode);
}

void AuditdFimInodeMap::clear() {
  data_.clear();
}

AuditdFimFdMap::AuditdFimFdMap(pid_t process_id) {
  setProcessId(process_id);
}

void AuditdFimFdMap::setProcessId(pid_t process_id) {
  process_id_ = process_id;
}

bool AuditdFimFdMap::getReference(AuditdFimFdDescriptor*& fd_desc,
                                  std::uint64_t fd) {
  auto it = data_.find(fd);
  if (it == data_.end()) {
    printUntrackedFdWarning(fd);
    return false;
  }

  fd_desc = &it->second;
  return true;
}

bool AuditdFimFdMap::duplicate(std::uint64_t fd, std::uint64_t new_fd) {
  auto it = data_.find(fd);
  if (it == data_.end()) {
    printUntrackedFdWarning(fd);
    return false;
  }

  data_.insert({new_fd, it->second});
  return true;
}

bool AuditdFimFdMap::takeAndRemove(AuditdFimFdDescriptor& fd_desc,
                                   std::uint64_t fd) {
  auto it = data_.find(fd);
  if (it == data_.end()) {
    printUntrackedFdWarning(fd);
    return false;
  }

  fd_desc = it->second;
  data_.erase(it);

  return true;
}

void AuditdFimFdMap::save(std::uint64_t fd,
                          ino_t inode,
                          AuditdFimFdDescriptor::OperationType last_operation) {
  AuditdFimFdDescriptor fd_desc;
  fd_desc.inode = inode;
  fd_desc.last_operation = last_operation;

  data_.insert({fd, fd_desc});
}

void AuditdFimFdMap::clear() {
  data_.clear();
}

void AuditdFimFdMap::printUntrackedFdWarning(std::uint64_t fd) {
  if (!FLAGS_audit_show_untracked_res_warnings) {
    return;
  }

  auto current_time = std::time(nullptr);
  bool show_warning = false;

  if ((current_time - warning_suppression_timer_) > 300) {
    warning_suppression_timer_ = current_time;
    show_warning = true;
  }

  if (show_warning) {
    VLOG(1) << "Untracked file descriptor from process " << process_id_;
  }
}

bool AuditdFimProcessMap::getReference(AuditdFimFdDescriptor*& fd_desc,
                                       pid_t process_id,
                                       std::uint64_t fd) {
  auto process_it = data_.find(process_id);
  if (process_it == data_.end()) {
    printUntrackedPidWarning(process_id);
    return false;
  }

  AuditdFimFdMap& fd_map = process_it->second;
  return fd_map.getReference(fd_desc, fd);
}

void AuditdFimProcessMap::create(pid_t process_id) {
  auto process_it = data_.find(process_id);
  if (process_it != data_.end()) {
    process_it->second.clear();
  } else {
    data_.insert({process_id, AuditdFimFdMap(process_id)});
  }
}

bool AuditdFimProcessMap::duplicate(pid_t process_id,
                                    std::uint64_t fd,
                                    std::uint64_t new_fd) {
  auto process_it = data_.find(process_id);
  if (process_it == data_.end()) {
    printUntrackedPidWarning(process_id);
    return false;
  }

  AuditdFimFdMap& fd_map = process_it->second;
  return fd_map.duplicate(fd, new_fd);
}

bool AuditdFimProcessMap::clone(pid_t old_pid, pid_t new_pid) {
  auto process_it = data_.find(old_pid);
  if (process_it == data_.end()) {
    printUntrackedPidWarning(old_pid);
    return false;
  }

  AuditdFimFdMap fd_map = process_it->second;
  fd_map.setProcessId(new_pid);

  data_.insert({new_pid, fd_map});
  return true;
}

bool AuditdFimProcessMap::takeAndRemove(AuditdFimFdDescriptor& fd_desc,
                                        pid_t process_id,
                                        std::uint64_t fd) {
  auto process_it = data_.find(process_id);
  if (process_it == data_.end()) {
    printUntrackedPidWarning(process_id);
    return false;
  }

  AuditdFimFdMap& fd_map = process_it->second;
  return fd_map.takeAndRemove(fd_desc, fd);
}

void AuditdFimProcessMap::save(
    std::uint64_t fd,
    pid_t process_id,
    ino_t inode,
    AuditdFimFdDescriptor::OperationType last_operation) {
  auto process_it = data_.find(process_id);
  if (process_it == data_.end()) {
    process_it = data_.insert({process_id, AuditdFimFdMap(process_id)}).first;

    // Try to limit the amount of processes we are tracking. When
    // removing, start from the oldest ones
    if (data_.size() > 4096) {
      data_.erase(data_.begin());
    }
  }

  AuditdFimFdMap& fd_map = process_it->second;
  return fd_map.save(fd, inode, last_operation);
}

void AuditdFimProcessMap::clear() {
  data_.clear();
}

void AuditdFimProcessMap::printUntrackedPidWarning(pid_t pid) {
  if (!FLAGS_audit_show_untracked_res_warnings) {
    return;
  }

  bool show_warning = false;
  auto current_time = std::time(nullptr);

  auto it = warning_suppression_filter_.find(pid);
  if (it == warning_suppression_filter_.end()) {
    warning_suppression_filter_[pid] = current_time;
    if (warning_suppression_filter_.size() > 2000) {
      warning_suppression_filter_.erase(warning_suppression_filter_.begin());
    }

    show_warning = true;

  } else {
    std::time_t elapsed_time = current_time - it->second;
    if (elapsed_time > 300) {
      show_warning = true;
    }
  }

  if (show_warning) {
    VLOG(1) << "Untracked process with pid " << pid;
  }
}
}
