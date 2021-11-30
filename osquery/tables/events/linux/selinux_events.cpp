/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core/flags.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/events/linux/selinux_events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/events/linux/selinux_events.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
FLAG(bool,
     audit_allow_selinux_events,
     false,
     "Allow the audit publisher to process audit events");

REGISTER(SELinuxEventSubscriber, "event_subscriber", "selinux_events");

Status SELinuxEventSubscriber::init() {
  if (!FLAGS_audit_allow_selinux_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&SELinuxEventSubscriber::Callback, sc);

  return Status::success();
}

Status SELinuxEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(emitted_row_list);

  return Status::success();
}

Status SELinuxEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::SELinux) {
      continue;
    }

    for (const auto& record : event.record_list) {
      Row r;

      auto record_pretty_name_it = kSELinuxRecordLabels.find(record.type);
      if (record_pretty_name_it == kSELinuxRecordLabels.end()) {
        r["type"] = std::to_string(record.type);
      } else {
        r["type"] = record_pretty_name_it->second;
      }

      r["message"] = record.raw_data;
      r["uptime"] = std::to_string(getUptime());
      emitted_row_list.push_back(r);
    }
  }

  return Status::success();
}

const std::set<int>& SELinuxEventSubscriber::GetEventSet() noexcept {
  return kSELinuxEventList;
}

} // namespace osquery
