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
#include "osquery/events/linux/auditeventpublisher.h"

namespace osquery {
DECLARE_bool(audit_allow_fim_events);
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);

REGISTER(AuditEventPublisher, "event_publisher", "auditeventpublisher");

namespace {
bool IsPublisherEnabled() noexcept {
  return (FLAGS_audit_allow_fim_events || FLAGS_audit_allow_process_events || FLAGS_audit_allow_sockets);
}
}

Status AuditEventPublisher::setUp() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  return Status(0, "OK");
}

void AuditEventPublisher::configure() {
  if (!IsPublisherEnabled()) {
    return;
  }

  // Only subscribe if we are actually going to have listeners
  if (audit_netlink_subscription_ == 0) {
    audit_netlink_subscription_ = AuditdNetlink::get().subscribe();
  }
}

void AuditEventPublisher::tearDown() {
  if (audit_netlink_subscription_ != 0) {
    AuditdNetlink::get().unsubscribe(audit_netlink_subscription_);
    audit_netlink_subscription_ = 0;
  }
}

Status AuditEventPublisher::run() {
  if (!IsPublisherEnabled()) {
    return Status(1, "Publisher disabled via configuration");
  }

  // Request our event queue from the AuditdNetlink component
  auto audit_event_record_queue =
      AuditdNetlink::get().getEvents(audit_netlink_subscription_);

  auto event_context = createEventContext();
  ProcessEvents(
      event_context, audit_event_record_queue, audit_trace_context_);

  if (!event_context->audit_events.empty()) {
    fire(event_context);
  }

  return Status(0, "OK");
}

void AuditEventPublisher::ProcessEvents(
    AuditEventContextRef event_context,
    const std::vector<AuditEventRecord>& record_list,
    AuditTraceContext& trace_context) noexcept {
  // Assemble each record into a AuditEvent object; an event is
  // complete when we receive the terminator (AUDIT_EOE)
  for (const auto& audit_event_record : record_list) {
    auto audit_event_it = trace_context.find(audit_event_record.audit_id);

    // We have two entry points here; the first one is for user messages, while
    // the second one is for syscalls
    if (audit_event_record.type >= AUDIT_FIRST_USER_MSG && audit_event_record.type <= AUDIT_LAST_USER_MSG) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::UserEvent;

      UserAuditEventData data;
      data.user_event_id = audit_event_record.type;
      audit_event.data = data;

      audit_event.record_list.push_back(audit_event_record);
      trace_context[audit_event_record.audit_id] = std::move(audit_event);

    } else if (audit_event_record.type == AUDIT_SYSCALL) {
      if (audit_event_it != trace_context.end()) {
        VLOG(1) << "Received a duplicated event.";
        trace_context.erase(audit_event_it);
      }

      AuditEvent audit_event;
      audit_event.type = AuditEvent::Type::Syscall;

      SyscallAuditEventData data;

      if (!GetIntegerFieldFromMap(data.syscall_number, audit_event_record.fields, "syscall")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The syscall field "
                "is either missing or not valid.";

        continue;
      }

      std::string syscall_status;
      GetStringFieldFromMap(syscall_status, audit_event_record.fields, "success", "yes");

      // By discarding this event, we will also automatically discard any other attached
      // record
      if (syscall_status != "yes") {
        continue;
      }

      std::uint64_t process_id;
      if (!GetIntegerFieldFromMap(process_id, audit_event_record.fields, "pid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The process id "
                "field is either missing or not valid.";

        continue;
      }

      std::uint64_t parent_process_id;
      if (!GetIntegerFieldFromMap(parent_process_id, audit_event_record.fields, "ppid")) {
        VLOG(1) << "Malformed AUDIT_SYSCALL record received. The parent "
                "process id field is either missing or not valid.";

        continue;
      }

      data.process_id = static_cast<pid_t>(process_id);
      data.parent_process_id = static_cast<pid_t>(parent_process_id);

      pid_t osquery_pid = getpid();
      if (data.process_id == osquery_pid || data.parent_process_id == osquery_pid) {
        continue;
      }

      audit_event.data = data;

      audit_event.record_list.push_back(audit_event_record);
      trace_context[audit_event_record.audit_id] = std::move(audit_event);

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

const AuditEventRecord *GetEventRecord(const AuditEvent &event, int record_type) noexcept {
  auto it = std::find_if(event.record_list.begin(), event.record_list.end(),
                         [record_type](const AuditEventRecord &record) -> bool {
                             return (record.type == record_type);
                         });

  if (it == event.record_list.end()) {
    return nullptr;
  }

  return &(*it);
};

bool GetStringFieldFromMap(std::string &value, const std::map<std::string, std::string> &fields, const std::string &name, const std::string &default_value) noexcept {
  auto it = fields.find(name);
  if (it == fields.end()) {
    value = default_value;
    return false;
  }

  value = it->second;
  return true;
}

bool GetIntegerFieldFromMap(std::uint64_t& value, const std::map<std::string, std::string>& field_map, const std::string& field_name, std::size_t base, std::uint64_t default_value) noexcept {
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
}
