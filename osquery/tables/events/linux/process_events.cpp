/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/process_events.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/linux/process_events.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/uptime.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <sys/stat.h>

namespace osquery {
namespace {
const std::unordered_map<int, std::string> kSyscallNameMap = {
    {__NR_execve, "execve"},
    {__NR_execveat, "execveat"},
    {__NR_clone, "clone"},
    {__NR_kill, "kill"},
    {__NR_tkill, "tkill"},
    {__NR_tgkill, "tgkill"},
#ifdef __x86_64__
    {__NR_fork, "fork"},
    {__NR_vfork, "vfork"},
#endif /* __x86_64__ */
};

enum class AuditArgumentFieldType {
  Value,
  Length,
  Chunk,
};

struct AuditArgumentField final {
  std::size_t argument_index{0U};
  std::size_t chunk_index{0U};
  AuditArgumentFieldType type{AuditArgumentFieldType::Value};
};

struct AuditArgument final {
  bool has_value{false};
  std::string value;

  bool has_declared_length{false};
  std::size_t declared_length{0U};

  std::map<std::size_t, std::string> chunks;
};

bool ParseCanonicalSize(std::size_t& output,
                        const std::string& value) noexcept {
  if (value.empty() ||
      !std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isdigit(character);
      })) {
    return false;
  }

  auto parsed_value = tryTo<std::size_t>(value);
  if (parsed_value.isError()) {
    return false;
  }

  output = parsed_value.take();
  return std::to_string(output) == value;
}

bool IsValidAuditArgumentValue(const std::string& value) noexcept {
  if (value.size() >= 2U && value.front() == '"' && value.back() == '"') {
    return value.find('"', 1U) == value.size() - 1U;
  }

  return !value.empty() && value.size() % 2U == 0U &&
         std::all_of(value.begin(), value.end(), [](unsigned char character) {
           return std::isxdigit(character);
         });
}

bool ParseAuditArgumentField(AuditArgumentField& output,
                             const std::string& field_name) noexcept {
  if (field_name.size() < 2U || field_name.front() != 'a') {
    return false;
  }

  std::size_t offset{1U};
  while (offset < field_name.size() &&
         std::isdigit(static_cast<unsigned char>(field_name[offset]))) {
    ++offset;
  }

  if (offset == 1U) {
    return false;
  }

  if (!ParseCanonicalSize(output.argument_index,
                          field_name.substr(1U, offset - 1U))) {
    return false;
  }

  if (offset == field_name.size()) {
    output.type = AuditArgumentFieldType::Value;
    return true;
  }

  if (field_name.compare(offset, std::string::npos, "_len") == 0) {
    output.type = AuditArgumentFieldType::Length;
    return true;
  }

  if (field_name[offset] != '[' || field_name.back() != ']' ||
      offset + 2U > field_name.size()) {
    return false;
  }

  if (!ParseCanonicalSize(
          output.chunk_index,
          field_name.substr(offset + 1U, field_name.size() - offset - 2U))) {
    return false;
  }

  output.type = AuditArgumentFieldType::Chunk;
  return true;
}

Status ReconstructAuditArguments(std::string& output,
                                 bool& reconstruction_incomplete,
                                 bool allow_zero_argc_with_a0,
                                 const AuditEvent& event) noexcept {
  std::map<std::size_t, AuditArgument> argument_map;
  bool execve_record_found{false};
  bool argc_found{false};
  std::size_t argc{0U};

  reconstruction_incomplete = false;

  for (const auto& record : event.record_list) {
    if (record.type != AUDIT_EXECVE) {
      continue;
    }

    execve_record_found = true;

    for (const auto& field : record.fields) {
      if (field.first == "argc") {
        std::size_t parsed_argc{0U};
        if (!ParseCanonicalSize(parsed_argc, field.second) || argc_found) {
          reconstruction_incomplete = true;
          continue;
        }

        argc = parsed_argc;
        argc_found = true;
        continue;
      }

      AuditArgumentField argument_field;
      if (!ParseAuditArgumentField(argument_field, field.first)) {
        if (field.first.size() > 1U && field.first.front() == 'a' &&
            std::isdigit(static_cast<unsigned char>(field.first[1U]))) {
          reconstruction_incomplete = true;
        }

        continue;
      }

      auto& argument = argument_map[argument_field.argument_index];

      if (argument_field.type == AuditArgumentFieldType::Value) {
        if (argument.has_value) {
          reconstruction_incomplete = true;
          continue;
        }

        argument.has_value = true;
        argument.value = field.second;

      } else if (argument_field.type == AuditArgumentFieldType::Length) {
        std::size_t parsed_length{0U};
        if (!ParseCanonicalSize(parsed_length, field.second) ||
            argument.has_declared_length) {
          reconstruction_incomplete = true;
          continue;
        }

        argument.declared_length = parsed_length;
        argument.has_declared_length = true;

      } else if (!argument.chunks
                      .emplace(argument_field.chunk_index, field.second)
                      .second) {
        reconstruction_incomplete = true;
      }
    }
  }

  if (!execve_record_found) {
    return Status::failure("Malformed AUDIT_EXECVE event");
  }

  output.clear();
  bool first_argument{true};
  std::size_t expected_argument_index{0U};

  for (const auto& argument_entry : argument_map) {
    if (argument_entry.first != expected_argument_index) {
      reconstruction_incomplete = true;
    }

    if (expected_argument_index != std::numeric_limits<std::size_t>::max()) {
      ++expected_argument_index;
    }

    const auto& argument = argument_entry.second;
    std::string value;

    if (argument.has_value) {
      if (argument.has_declared_length || !argument.chunks.empty()) {
        reconstruction_incomplete = true;
      }

      if (!IsValidAuditArgumentValue(argument.value)) {
        reconstruction_incomplete = true;
      }

      value = DecodeAuditPathValues(argument.value);

    } else {
      if (!argument.has_declared_length || argument.chunks.empty()) {
        reconstruction_incomplete = true;
      }

      std::size_t encoded_length{0U};
      std::size_t expected_chunk_index{0U};

      for (const auto& chunk : argument.chunks) {
        if (chunk.first != expected_chunk_index) {
          reconstruction_incomplete = true;
        }

        if (expected_chunk_index != std::numeric_limits<std::size_t>::max()) {
          ++expected_chunk_index;
        }

        const bool quoted = chunk.second.size() >= 2U &&
                            chunk.second.front() == '"' &&
                            chunk.second.back() == '"';
        const auto chunk_encoded_length =
            quoted ? chunk.second.size() - 2U : chunk.second.size();

        if (chunk_encoded_length >
            std::numeric_limits<std::size_t>::max() - encoded_length) {
          reconstruction_incomplete = true;
        } else {
          encoded_length += chunk_encoded_length;
        }

        if (!IsValidAuditArgumentValue(chunk.second)) {
          reconstruction_incomplete = true;
        }

        value += DecodeAuditPathValues(chunk.second);
      }

      if (argument.has_declared_length &&
          encoded_length != argument.declared_length) {
        reconstruction_incomplete = true;
      }
    }

    if (!first_argument) {
      output += ' ';
    }

    output += value;
    first_argument = false;
  }

  // Some observed execveat records report argc=0 while still carrying a0.
  const bool argc_matches =
      argc_found &&
      ((argc > 0U && argc == argument_map.size()) ||
       (argc == 0U && argument_map.empty()) ||
       (argc == 0U && allow_zero_argc_with_a0 && argument_map.size() == 1U &&
        argument_map.begin()->first == 0U &&
        argument_map.begin()->second.has_value &&
        !argument_map.begin()->second.has_declared_length &&
        argument_map.begin()->second.chunks.empty()));

  if (!argc_matches) {
    reconstruction_incomplete = true;
  }

  return Status::success();
}
} // namespace

DECLARE_bool(audit_allow_process_events);

REGISTER(AuditProcessEventSubscriber, "event_subscriber", "process_events");

Status AuditProcessEventSubscriber::init() {
  if (!FLAGS_audit_allow_process_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&AuditProcessEventSubscriber::Callback, sc);

  return Status::success();
}

Status AuditProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  for (auto& row : emitted_row_list) {
    struct stat file_stat;
    if (!stat(row.at("path").c_str(), &file_stat)) {
      if (row["mode"].empty()) {
        row["mode"] = lsperms(file_stat.st_mode);
      }
      row["btime"] = "0";
      row["atime"] = BIGINT(file_stat.st_atime);
      row["mtime"] = BIGINT(file_stat.st_mtime);
      row["ctime"] = BIGINT(file_stat.st_ctime);
    } else {
      VLOG(1) << "Failed to stat path: " << row.at("path");
      row["ctime"] = "0";
      row["atime"] = "0";
      row["mtime"] = "0";
    }
  }

  addBatch(emitted_row_list);
  return Status::success();
}

Status AuditProcessEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  // clang-format off
  /*
    execve (59)
    1300 audit(1502125323.756:6): arch=c000003e syscall=59 success=yes exit=0 a0=23eb8e0 a1=23ebbc0 a2=23c9860 a3=7ffe18d32ed0 items=2 ppid=6882 pid=7841 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 comm="sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
    1309 audit(1502125323.756:6): argc=1 a0="sh"
    1307 audit(1502125323.756:6):  cwd="/home/alessandro"
    1302 audit(1502125323.756:6): item=0 name="/usr/bin/sh" inode=18867 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 objtype=NORMAL
    1302 audit(1502125323.756:6): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=33604032 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL
    1320 audit(1502125323.756:6):

    execveat (322)
    1300, audit(1565728125.289:26): arch=c000003e syscall=322 success=yes exit=0 a0=3 a1=5627914857d5 a2=0 a3=0 items=2 ppid=31922 pid=29003 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=4294967295 comm="fork" exe="/home/alessandro/fork" key=(null)
    1309, audit(1565728125.289:26): argc=0 a0="/dev/fd/3/fork"
    1307, audit(1565728125.289:26): cwd="/home/alessandro"
    1302, audit(1565728125.289:26): item=0 name="fork" inode=1440185 dev=00:32 mode=0100775 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
    1302, audit(1565728125.289:26): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=6763 dev=00:19 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
    1327, audit(1565728125.289:26): proctitle="./execveat"
    1320, audit(1565728125.289:26):

    fork (57), clone (56), vfork (58)
    1300 audit(1565629510.716:246170): arch=c000003e syscall=57 success=yes exit=13733 a0=7fff45d30a68 a1=7fff45d30a78 a2=55a2507aa680 a3=7f92b823cd80 items=0 ppid=9680 pid=13732 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=4294967295 comm="fork" exe="/home/alessandro/fork" key=(null)
    1327 audit(1565629510.716:246170): proctitle="./fork"
    1320 audit(1565629510.716:246170):
  */
  // clang-format on

  emitted_row_list.clear();
  emitted_row_list.reserve(event_list.size());

  for (const auto& event : event_list) {
    // Make sure this is a syscall event that we are interested in
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
    if (!event_data.succeeded) {
      continue;
    }

    bool is_exec_syscall{false};
    bool is_kill_syscall{false};
    if (kExecProcessEventsSyscalls.count(event_data.syscall_number) > 0U) {
      is_exec_syscall = true;

    } else if (kForkProcessEventsSyscalls.count(event_data.syscall_number) >
               0U) {
      is_exec_syscall = false;

    } else if (kKillProcessEventsSyscalls.count(event_data.syscall_number) >
               0U) {
      is_kill_syscall = true;

    } else {
      continue;
    }

    // Acquire the base syscall record, which is common to all the different
    // events we are handling here
    const AuditEventRecord* syscall_event_record =
        GetEventRecord(event, AUDIT_SYSCALL);

    if (syscall_event_record == nullptr) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event";
      continue;
    }

    // Skip threads created with the CLONE_THREAD flag of the clone() system
    // call
    bool is_thread = false;
    auto status = IsThreadClone(
        is_thread, event_data.syscall_number, *syscall_event_record);

    if (!status.ok()) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event: " << status.getMessage();
      continue;
    }

    if (is_thread) {
      continue;
    }

    // Generate basic row contents
    Row row = {};
    row["uptime"] = std::to_string(getUptime());

    CopyFieldFromMap(row, syscall_event_record->fields, "auid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "uid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "euid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "fsuid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "suid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "gid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "egid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "fsgid", "0");
    CopyFieldFromMap(row, syscall_event_record->fields, "sgid", "0");

    if (!GetSyscallName(row["syscall"], event_data.syscall_number)) {
      row["syscall"] = std::to_string(event_data.syscall_number);
      VLOG(1) << "Failed to locate the system call name: "
              << event_data.syscall_number;
    }

    std::string field_value;
    GetStringFieldFromMap(field_value, syscall_event_record->fields, "exe", "");
    row["path"] = DecodeAuditPathValues(field_value);

    // Acquire the process IDs
    std::uint64_t parent_process_id{0U};
    std::uint64_t process_id{0U};
    auto s = GetProcessIDs(parent_process_id,
                           process_id,
                           event_data.syscall_number,
                           *syscall_event_record);
    if (!s.ok()) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event: " << status.getMessage();
      continue;
    }

    row["parent"] = std::to_string(parent_process_id);
    row["pid"] = std::to_string(process_id);

    // Unused fields
    row["overflows"] = "";
    row["env"] = "";
    row["env_size"] = "0";
    row["env_count"] = "0";

    // Handle syscall-specific data
    if (is_exec_syscall) {
      auto status = ProcessExecveEventData(row, event);
      if (!status) {
        VLOG(1) << "Failed to parse the event: " << status.getMessage();
        continue;
      }

    } else if (is_kill_syscall) {
      const AuditEventRecord* obj_pid_record =
          GetEventRecord(event, AUDIT_OBJ_PID);
      if (obj_pid_record == nullptr) {
        VLOG(1) << "Failed to parse the event: malformed or absent "
                   "AUDIT_OBJ_PID record, using defaults";
      }
      using ObjPidType = decltype(obj_pid_record->fields);
      const auto&& obj_pid_fields =
          (obj_pid_record ? obj_pid_record->fields : ObjPidType{});

      CopyFieldFromMap(row, syscall_event_record->fields, "tty", "");
      CopyFieldFromMap(row, syscall_event_record->fields, "ses", "-1");
      CopyFieldFromMap(row, syscall_event_record->fields, "comm", "");
      CopyFieldFromMap(row, obj_pid_fields, "ocomm", "");
      CopyFieldFromMap(row, obj_pid_fields, "oses", "-1");
      CopyFieldFromMap(row, obj_pid_fields, "oauid", "-1");

    } else {
      row["owner_uid"] = "0";
      row["owner_gid"] = "0";
    }

    emitted_row_list.emplace_back(row);
  }

  return Status::success();
}

Status AuditProcessEventSubscriber::ProcessExecveEventData(
    Row& row, const AuditEvent& event) noexcept {
  // Get the initial working directory of the process
  const AuditEventRecord* cwd_event_record = GetEventRecord(event, AUDIT_CWD);
  if (cwd_event_record == nullptr) {
    return Status::failure("Malformed AUDIT_CWD event");
  }

  CopyFieldFromMap(row, cwd_event_record->fields, "cwd", "");

  bool cmdline_incomplete{false};
  const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
  const bool allow_zero_argc_with_a0 =
      event_data.syscall_number == __NR_execveat;

  auto status = ReconstructAuditArguments(
      row["cmdline"], cmdline_incomplete, allow_zero_argc_with_a0, event);
  if (!status.ok()) {
    return status;
  }

  if (cmdline_incomplete) {
    row["overflows"] = "cmdline";
  }

  row["cmdline_size"] = std::to_string(row["cmdline"].size());

  // Get the remaining data from the first AUDIT_PATH record
  const AuditEventRecord* first_path_event_record =
      GetEventRecord(event, AUDIT_PATH);

  if (first_path_event_record == nullptr) {
    return Status::failure("Malformed AUDIT_PATH event");
  }

  CopyFieldFromMap(row, first_path_event_record->fields, "mode", "");

  GetStringFieldFromMap(
      row["owner_uid"], first_path_event_record->fields, "ouid", "0");

  GetStringFieldFromMap(
      row["owner_gid"], first_path_event_record->fields, "ogid", "0");

  return Status::success();
}

Status AuditProcessEventSubscriber::GetProcessIDs(
    std::uint64_t& parent_process_id,
    std::uint64_t& process_id,
    int syscall_nr,
    const AuditEventRecord& syscall_record) noexcept {
  parent_process_id = 0U;
  process_id = 0U;

  if (syscall_record.type != AUDIT_SYSCALL) {
    return Status::failure("Invalid record type");
  }

  if (0
#ifdef __x86_64__
      || syscall_nr == __NR_fork || syscall_nr == __NR_vfork
#endif /*  __x86_64__ */
  ) {
    GetIntegerFieldFromMap(parent_process_id, syscall_record.fields, "pid");
    GetIntegerFieldFromMap(process_id, syscall_record.fields, "exit");

  } else if (syscall_nr == __NR_clone) {
    GetIntegerFieldFromMap(process_id, syscall_record.fields, "exit");

    std::uint64_t clone_flags{0U};
    GetIntegerFieldFromMap(clone_flags, syscall_record.fields, "a0", 16U);

    if ((clone_flags & CLONE_PARENT) != 0) {
      GetIntegerFieldFromMap(parent_process_id, syscall_record.fields, "ppid");
    } else {
      GetIntegerFieldFromMap(parent_process_id, syscall_record.fields, "pid");
    }

  } else {
    GetIntegerFieldFromMap(parent_process_id, syscall_record.fields, "ppid");
    GetIntegerFieldFromMap(process_id, syscall_record.fields, "pid");
  }

  return Status::success();
}

Status AuditProcessEventSubscriber::IsThreadClone(
    bool& is_thread_clone,
    int syscall_nr,
    const AuditEventRecord& syscall_record) noexcept {
  is_thread_clone = false;

  if (syscall_record.type != AUDIT_SYSCALL) {
    return Status::failure("Invalid record type");
  }

  if (syscall_nr != __NR_clone) {
    return Status::success();
  }

  std::uint64_t clone_flags;
  GetIntegerFieldFromMap(clone_flags, syscall_record.fields, "a0", 16U);

  is_thread_clone = (clone_flags & CLONE_THREAD) != 0U;
  return Status::success();
}

bool AuditProcessEventSubscriber::GetSyscallName(std::string& name,
                                                 int syscall_nr) noexcept {
  name.clear();

  auto it = kSyscallNameMap.find(syscall_nr);
  if (it == kSyscallNameMap.end()) {
    return false;
  }

  name = it->second;
  return true;
}

const std::unordered_map<int, std::string>&
AuditProcessEventSubscriber::GetSyscallNameMap() noexcept {
  return kSyscallNameMap;
}
} // namespace osquery
