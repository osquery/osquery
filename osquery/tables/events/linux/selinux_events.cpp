/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/selinux_events.h"

namespace osquery {
FLAG(bool,
     audit_allow_selinux_events,
     false,
     "Allow the audit publisher to process audit events");

REGISTER(SELinuxEventSubscriber, "event_subscriber", "selinux_events");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

Status SELinuxEventSubscriber::init() {
  if (!FLAGS_audit_allow_selinux_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&SELinuxEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status SELinuxEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
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
      r["uptime"] = std::to_string(tables::getUptime());
      emitted_row_list.push_back(r);
    }
  }

  return Status(0, "Ok");
}

const std::set<int>& SELinuxEventSubscriber::GetEventSet() noexcept {
  return kSELinuxEventList;
}
} // namespace osquery
