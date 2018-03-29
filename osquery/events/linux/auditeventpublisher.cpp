/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <array>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/selinux_events.h"

namespace osquery {
/// The audit subsystem may have a performance impact on the system.
FLAG(bool,
     disable_audit,
     true,
     "Disable receiving events from the audit subsystem");

// External flags; they are used to determine whether we should run or not
DECLARE_bool(audit_allow_fim_events);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);
DECLARE_bool(audit_allow_user_events);
DECLARE_bool(audit_allow_selinux_events);

REGISTER(AuditEventPublisher, "event_publisher", "auditeventpublisher");

namespace {
bool IsPublisherEnabled() noexcept {
  if (FLAGS_disable_audit) {
    return false;
  }

  return (FLAGS_audit_allow_fim_events || FLAGS_audit_allow_process_events ||
          FLAGS_audit_allow_sockets || FLAGS_audit_allow_user_events ||
          FLAGS_audit_allow_selinux_events);
}
} // namespace

std::string AuditEventPublisher::executable_path_;

Status AuditEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  if (executable_path_.empty()) {
    char buffer[PATH_MAX] = {};
    assert(readlink("/proc/self/exe", buffer, sizeof(buffer)) != -1);
    executable_path_ = buffer;
  }

  return Status(0, "OK");
}

void AuditEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    return;
  }

  audit_netlink_ = std::make_unique<AuditdNetlink>();
}

void AuditEventPublisher::tearDown() {
  if (!IsPublisherEnabled()) {
    return;
  }

  audit_netlink_.reset();
}

Status AuditEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  auto audit_event_record_queue = audit_netlink_->getEvents();

  auto event_context = createEventContext();
  ProcessEvents(event_context, audit_event_record_queue, audit_trace_context_);

  if (!event_context->audit_events.empty()) {
    fire(event_context);
  }

  return Status(0, "OK");
}

void AuditEventPublisher::ProcessEvents(
    AuditEventContextRef event_context,
    const std::vector<AuditEventRecord>& record_list,
    AuditTraceContext& trace_context) noexcept {
  static const auto& selinux_event_set = SELinuxEventSubscriber::GetEventSet();

  // Assemble each record into a AuditEvent object; multi-record events
  // are complete when we receive the terminator (AUDIT_EOE)
  for (const auto& audit_event_record : record_list) {
    auto audit_event_it = trace_context.find(audit_event_record.audit_id);

    // We have two entry points here; the first one is for user messages, while
    // the second one is for syscalls
    if (audit_event_record.type >= AUDIT_FIRST_USER_MSG &&
        audit_event_record.type <= AUDIT_LAST_USER_MSG) {
      UserAuditEventData data = {};
      data.user_event_id = static_cast<std::uint64_t>(audit_event_record.type);

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::UserEvent;
      audit_event.record_list.push_back(audit_event_record);
      audit_event.data = data;

      event_context->audit_events.push_back(audit_event);

      // SELinux events
    } else if (selinux_event_set.find(audit_event_record.type) !=
               selinux_event_set.end()) {
      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::SELinux;
      audit_event.record_list.push_back(audit_event_record);

      event_context->audit_events.push_back(audit_event);

    } else if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::Syscall;

      SyscallAuditEventData data;

      std::string raw_executable_path;
      if (!GetStringFieldFromMap(
              raw_executable_path, audit_event_record.fields, "exe")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
                   "executable path field is either missing or not valid.";

        continue;
      }

      data.executable_path = DecodeAuditPathValues(raw_executable_path);

      // Do not process events originated by the osquery watchdog or daemon
      if (executable_path_ == data.executable_path) {
        continue;
      }

      if (!GetIntegerFieldFromMap(
              data.syscall_number, audit_event_record.fields, "syscall")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The "
                   "syscall field "
                   "is either missing or not valid.";

        continue;
      }

      std::string syscall_status;
      GetStringFieldFromMap(
          syscall_status, audit_event_record.fields, "success", "yes");

      // By discarding this event, we will also automatically discard any other
      // attached record
      if (syscall_status != "yes") {
        continue;
      }

      std::uint64_t process_id;
      if (!GetIntegerFieldFromMap(
              process_id, audit_event_record.fields, "pid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The process id "
                   "field is either missing or not valid.";

        continue;
      }

      std::uint64_t parent_process_id;
      if (!GetIntegerFieldFromMap(
              parent_process_id, audit_event_record.fields, "ppid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
                   "process id field is either missing or not valid.";

        continue;
      }

      data.process_id = static_cast<pid_t>(process_id);
      data.parent_process_id = static_cast<pid_t>(parent_process_id);
      audit_event.data = data;

      std::uint64_t process_uid;
      if (!GetIntegerFieldFromMap(
              process_uid, audit_event_record.fields, "uid")) {
        VLOG(1) << "Missing or invalid uid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_euid;
      if (!GetIntegerFieldFromMap(
              process_euid, audit_event_record.fields, "euid")) {
        VLOG(1) << "Missing or invalid euid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_gid;
      if (!GetIntegerFieldFromMap(
              process_gid, audit_event_record.fields, "gid")) {
        VLOG(1) << "Missing or invalid gid field in AUDIT_SYSCALL";

        continue;
      }

      std::uint64_t process_egid;
      if (!GetIntegerFieldFromMap(
              process_egid, audit_event_record.fields, "egid")) {
        VLOG(1) << "Missing or invalid egid field in AUDIT_SYSCALL";

        continue;
      }

      data.process_uid = static_cast<uid_t>(process_uid);
      data.process_euid = static_cast<uid_t>(process_euid);
      data.process_gid = static_cast<gid_t>(process_gid);
      data.process_egid = static_cast<gid_t>(process_egid);

      audit_event.record_list.push_back(audit_event_record);
      trace_context[audit_event_record.audit_id] = std::move(audit_event);

      // This is the terminator for multi-record audit events
    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == trace_context.end()) {
        continue;
      }

      auto completed_audit_event = audit_event_it->second;
      trace_context.erase(audit_event_it);

      event_context->audit_events.push_back(completed_audit_event);

    } else {
      if (audit_event_it == trace_context.end()) {
        continue;
      }

      audit_event_it->second.record_list.push_back(audit_event_record);
    }
  }

  // Drop events that are older than 5 minutes; it means that we have failed to
  // receive the end of record and will never complete them correctly

  std::time_t current_time;
  std::time(&current_time);

  std::unordered_map<std::string, std::time_t> timestamp_cache;

  // The first part of the audit id is a timestamp: 1501323932.710:7670542
  for (auto event_it = trace_context.begin();
       event_it != trace_context.end();) {
    const auto& audit_event_id = event_it->first;
    std::time_t event_timestamp;

    auto timestamp_it = timestamp_cache.find(audit_event_id);
    if (timestamp_it == timestamp_cache.end()) {
      std::string string_timestamp = audit_event_id.substr(0, 10);

      long long int converted_value;
      if (!safeStrtoll(string_timestamp, 10, converted_value)) {
        event_timestamp = 0;
      } else {
        event_timestamp = static_cast<std::time_t>(converted_value);
      }

      timestamp_cache[audit_event_id] = event_timestamp;

    } else {
      event_timestamp = timestamp_it->second;
    }

    if (current_time - event_timestamp >= 300) {
      event_it = trace_context.erase(event_it);
    } else {
      event_it++;
    }
  }
}

const AuditEventRecord* GetEventRecord(const AuditEvent& event,
                                       int record_type) noexcept {
  auto it = std::find_if(event.record_list.begin(),
                         event.record_list.end(),
                         [record_type](const AuditEventRecord& record) -> bool {
                           return (record.type == record_type);
                         });

  if (it == event.record_list.end()) {
    return nullptr;
  }

  return &(*it);
};

bool GetStringFieldFromMap(std::string& value,
                           const std::map<std::string, std::string>& fields,
                           const std::string& name,
                           const std::string& default_value) noexcept {
  auto it = fields.find(name);
  if (it == fields.end()) {
    value = default_value;
    return false;
  }

  value = it->second;
  return true;
}

bool GetIntegerFieldFromMap(std::uint64_t& value,
                            const std::map<std::string, std::string>& field_map,
                            const std::string& field_name,
                            std::size_t base,
                            std::uint64_t default_value) noexcept {
  std::string string_value;
  if (!GetStringFieldFromMap(string_value, field_map, field_name, "")) {
    value = default_value;
    return false;
  }

  long long temp;
  if (!safeStrtoll(string_value, base, temp)) {
    value = default_value;
    return false;
  }

  value = static_cast<std::uint64_t>(temp);
  return true;
}

void CopyFieldFromMap(Row& row,
                      const std::map<std::string, std::string>& fields,
                      const std::string& name,
                      const std::string& default_value) noexcept {
  GetStringFieldFromMap(row[name], fields, name, default_value);
}
} // namespace osquery
