/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

#include "osquery/events/linux/auditeventpublisher.h"

namespace osquery {

FLAG(bool,
     audit_allow_user_events,
     false,
     "Allow the audit publisher to install user events-related rules");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

class UserEventSubscriber final : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status ProcessEvents(
      std::vector<Row>& emitted_row_list,
      const std::vector<AuditEvent>& event_list) noexcept;
};

REGISTER(UserEventSubscriber, "event_subscriber", "user_events");

Status UserEventSubscriber::init() {
  if (!FLAGS_audit_allow_user_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&UserEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status UserEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  for (auto& row : emitted_row_list) {
    add(row);
  }

  return Status(0, "Ok");
}

Status UserEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  auto L_CopyFieldFromMap = [](
      Row& row,
      const std::map<std::string, std::string>& fields,
      const std::string& name,
      const std::string& default_value = std::string()) -> void {
    GetStringFieldFromMap(row[name], fields, name, default_value);
  };

  emitted_row_list.clear();
  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::UserEvent) {
      continue;
    }

    for (const auto& record : event.record_list) {
      Row row = {};

      row["uptime"] = INTEGER(tables::getUptime());
      row["type"] = INTEGER(record.type);

      L_CopyFieldFromMap(row, record.fields, "uid", "");
      L_CopyFieldFromMap(row, record.fields, "pid", "");
      L_CopyFieldFromMap(row, record.fields, "auid", "");
      L_CopyFieldFromMap(row, record.fields, "terminal", "");

      GetStringFieldFromMap(row["address"], record.fields, "addr", "");

      std::string executable_path;
      GetStringFieldFromMap(executable_path, record.fields, "exe", "");
      row["path"] = DecodeAuditPathValues(executable_path);

      std::string message;
      GetStringFieldFromMap(message, record.fields, "msg", "");

      if (message.size() > 1) {
        message.erase(0, 1);
        row["message"] = message;
      }

      emitted_row_list.push_back(row);
    }
  }

  return Status(0, "Ok");
}
} // namespace osquery
