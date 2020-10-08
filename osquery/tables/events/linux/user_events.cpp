/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {

DECLARE_bool(audit_allow_user_events);

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

  return Status::success();
}

Status UserEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(emitted_row_list);
  return Status::success();
}

Status UserEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();

  emitted_row_list.reserve(event_list.size());

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::UserEvent) {
      continue;
    }

    for (const auto& record : event.record_list) {
      Row row = {};

      row["uptime"] = INTEGER(getUptime());
      row["type"] = INTEGER(record.type);

      CopyFieldFromMap(row, record.fields, "uid", "");
      CopyFieldFromMap(row, record.fields, "pid", "");
      CopyFieldFromMap(row, record.fields, "auid", "");
      CopyFieldFromMap(row, record.fields, "terminal", "");

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

  return Status::success();
}
} // namespace osquery
