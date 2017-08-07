/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/syscall_monitor.h"

namespace osquery {
DECLARE_bool(audit_allow_fim_events);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);

REGISTER(SyscallMonitorEventPublisher, "event_publisher", "syscallmonitor");

namespace {
bool IsPublisherEnabled() noexcept {
  return (FLAGS_audit_allow_fim_events || FLAGS_audit_allow_process_events || FLAGS_audit_allow_sockets);
}
/**
* @brief Returns the specified field from the record.
*
* Returns the specified field name from the given audit event record; if
* the field is missing, the user-supplied default value is returned
* instead
*/
bool GetAuditRecordField(
    std::string& value,
    const AuditEventRecord& record,
    const std::string& field_name,
    const std::string& default_value = std::string()) noexcept {
  const auto& field_map = record.fields;

  auto field_it = field_map.find(field_name);
  if (field_it == field_map.end()) {
    value = default_value;
    return false;
  }

  value = field_it->second;
  return true;
}

/**
* @brief Returns the specified field from the record.
*
* Returns the specified field name from the given audit event record,
* converting it to an unsigned integer; if the field is
* missing, the user-supplied default value is returned instead
*/
bool GetAuditRecordField(std::uint64_t& value,
                         const AuditEventRecord& record,
                         const std::string& field_name,
                         std::size_t base = 10,
                         std::uint64_t default_value = 0) noexcept {
  std::string string_value;
  if (!GetAuditRecordField(string_value, record, field_name, "")) {
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
}

Status SyscallMonitorEventPublisher::setUp() {
  if (!IsPublisherEnabled) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void SyscallMonitorEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    return;
  }

  // Only subscribe if we are actually going to have listeners
  if (audit_netlink_subscription_ == 0) {
    audit_netlink_subscription_ = AuditdNetlink::get().subscribe();
  }
}

void SyscallMonitorEventPublisher::tearDown() {
  if (audit_netlink_subscription_ != 0) {
    AuditdNetlink::get().unsubscribe(audit_netlink_subscription_);
    audit_netlink_subscription_ = 0;
  }
}

Status SyscallMonitorEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  // Request our event queue from the AuditdNetlink component
  auto audit_event_record_queue =
      AuditdNetlink::get().getEvents(audit_netlink_subscription_);

  auto event_context = createEventContext();
  ProcessEvents(
      event_context, audit_event_record_queue, syscall_trace_context_);

  if (!event_context->syscall_events.empty()) {
    fire(event_context);
  }

  return Status(0, "OK");
}

void SyscallMonitorEventPublisher::ProcessEvents(
    SyscallMonitorEventContextRef event_context,
    const std::vector<AuditEventRecord>& record_list,
    SyscallMonitorTraceContext& trace_context) noexcept {
  // Assemble each record into a SyscallMonitorEvent object; an event is
  // complete when we receive the terminator (AUDIT_EOE)
  for (const auto& audit_event_record : record_list) {
    auto audit_event_it = trace_context.find(audit_event_record.audit_id);

    if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      SyscallMonitorEvent syscall_event;
      if (!GetAuditRecordField(syscall_event.syscall_number, audit_event_record, "syscall")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The syscall field "
                "is either missing or not valid.";

        continue;
      }

      std::string syscall_status;
      GetAuditRecordField(syscall_status, audit_event_record, "success", "yes");

      // By discarding this event, we will also automatically discard any other attached
      // record
      if (syscall_status != "yes") {
        continue;
      }

      std::uint64_t process_id;
      if (!GetAuditRecordField(process_id, audit_event_record, "pid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The process id "
                "field is either missing or not valid.";

        continue;
      }

      std::uint64_t parent_process_id;
      if (!GetAuditRecordField(parent_process_id, audit_event_record, "ppid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
                "process id field is either missing or not valid.";

        continue;
      }

      syscall_event.process_id = static_cast<pid_t>(process_id);
      syscall_event.parent_process_id = static_cast<pid_t>(parent_process_id);

      pid_t osquery_pid = getpid();
      if (syscall_event.process_id == osquery_pid || syscall_event.parent_process_id == osquery_pid) {
        continue;
      }

      syscall_event.record_list.push_back(audit_event_record);
      trace_context[audit_event_record.audit_id] = std::move(syscall_event);

    } else if (audit_event_record.type == AUDIT_EOE) {
      if (audit_event_it == trace_context.end()) {
        continue;
      }

      auto completed_syscall_event = audit_event_it->second;
      trace_context.erase(audit_event_it);

      event_context->syscall_events.push_back(completed_syscall_event);

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
  for (auto syscall_it = trace_context.begin();
       syscall_it != trace_context.end();) {
    const auto& audit_event_id = syscall_it->first;
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
      syscall_it = trace_context.erase(syscall_it);
    } else {
      syscall_it++;
    }
  }
}
}
