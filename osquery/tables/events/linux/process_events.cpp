/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <asm/unistd_64.h>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/events/linux/syscall_monitor.h"

namespace osquery {

FLAG(bool,
     audit_allow_process_events,
     false,
     "Allow the audit publisher to install process event monitoring rules");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

class AuditProcessEventSubscriber : public EventSubscriber<SyscallMonitorEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status ProcessEvents(std::vector<Row> &emitted_row_list,
    const std::vector<SyscallMonitorEvent>& event_list) noexcept;
};

REGISTER(AuditProcessEventSubscriber, "event_subscriber", "process_events");

Status AuditProcessEventSubscriber::init() {
  if (!FLAGS_audit_allow_process_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&AuditProcessEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status AuditProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::cout << __func__ << "@" << __LINE__ << std::endl;

  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->syscall_events);
  if (!status.ok()) {
    return status;
  }

  for (auto &row : emitted_row_list) {
    add(row);
  }

  return Status(0, "Ok");
}

Status AuditProcessEventSubscriber::ProcessEvents(std::vector<Row> &emitted_row_list,
                                const std::vector<SyscallMonitorEvent>& event_list) noexcept {
  // clang-format off
  /*
    1300 audit(1502125323.756:6): arch=c000003e syscall=59 success=yes exit=0 a0=23eb8e0 a1=23ebbc0 a2=23c9860 a3=7ffe18d32ed0 items=2 ppid=6882 pid=7841 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 comm="sh" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
    1309 audit(1502125323.756:6): argc=1 a0="sh"
    1307 audit(1502125323.756:6):  cwd="/home/alessandro"
    1302 audit(1502125323.756:6): item=0 name="/usr/bin/sh" inode=18867 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 objtype=NORMAL
    1302 audit(1502125323.756:6): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=33604032 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL
    1320 audit(1502125323.756:6):
  */
  // clang-format on

  auto L_GetFieldFromMap = [](std::string &value, const std::map<std::string, std::string> &fields, const std::string &name, const std::string &default_value = std::string()) -> bool {
    auto it = fields.find(name);
    if (it == fields.end()) {
      value = default_value;
      return false;
    }

    value = it->second;
    return true;
  };

  auto L_CopyFieldFromMap = [L_GetFieldFromMap](Row &row, const std::map<std::string, std::string> &fields, const std::string &name, const std::string &default_value) -> void {
    L_GetFieldFromMap(row[name], fields, name, default_value);
  };

  auto L_GetEventRecord = [](const SyscallMonitorEvent &event, int record_type) -> const AuditEventRecord * {
    auto it = std::find_if(event.record_list.begin(), event.record_list.end(),
      [record_type](const AuditEventRecord &record) -> bool {
        return (record.type == record_type);
    });

    if (it == event.record_list.end()) {
      return nullptr;
    }

    return &(*it);
  };

  emitted_row_list.clear();

  for (const auto &event : event_list) {
    if (event.syscall_number != __NR_execve) {
      continue;
    }

    const AuditEventRecord *syscall_event_record = L_GetEventRecord(event, AUDIT_SYSCALL);
    if (syscall_event_record == nullptr) {
      VLOG(1) << "Malformed AUDIT_SYSCALL event";
      continue;
    }

    const AuditEventRecord *execve_event_record = L_GetEventRecord(event, AUDIT_EXECVE);
    if (execve_event_record == nullptr) {
      VLOG(1) << "Malformed AUDIT_EXECVE event";
      continue;
    }

    const AuditEventRecord *first_path_event_record = L_GetEventRecord(event, AUDIT_PATH);
    if (first_path_event_record == nullptr) {
      VLOG(1) << "Malformed AUDIT_PATH event";
      continue;
    }

    Row row = {};

    L_CopyFieldFromMap(row, syscall_event_record->fields, "auid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "pid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "ppid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "uid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "euid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "gid", "0");
    L_CopyFieldFromMap(row, syscall_event_record->fields, "egid", "0");

    L_GetFieldFromMap(row["path"], syscall_event_record->fields, "exe", "");
    L_GetFieldFromMap(row["cmdline"], syscall_event_record->fields, "comm", "");

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, row.at("path"));
    if (qd.size() == 1) {
      row["ctime"] = qd.front().at("ctime");
      row["atime"] = qd.front().at("atime");
      row["mtime"] = qd.front().at("mtime");
      row["btime"] = "0";
    }

    row["overflows"] = "";
    row["env_size"] = "0";
    row["env_count"] = "0";
    row["env"] = "";
    row["uptime"] = std::to_string(tables::getUptime());

    // build the command line from the AUDIT_EXECVE record
    for (const auto& arg : execve_event_record->fields) {
      if (arg.first == "argc") {
        continue;
      }

      // Amalgamate all the "arg*" fields.
      if (row.at("cmdline").size() > 0) {
        row["cmdline"] += " ";
      }

      row["cmdline"] += DecodeHexEncodedValue(arg.second);
    }

    // There may be a better way to calculate actual size from audit.
    // Then an overflow could be calculated/determined based on
    // actual/expected.
    row["cmdline_size"] = std::to_string(row.at("cmdline").size());

    // Get the remaining data from the first AUDIT_PATH record
    L_CopyFieldFromMap(row, first_path_event_record->fields, "mode", "");
    L_GetFieldFromMap(row["owner_uid"], first_path_event_record->fields, "ouid", "0");
    L_GetFieldFromMap(row["owner_gid"], first_path_event_record->fields, "ogid", "0");

    emitted_row_list.push_back(row);
  }

  return Status(0, "Ok");
}
}
