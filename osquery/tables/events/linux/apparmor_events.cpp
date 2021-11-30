/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/tables/events/linux/apparmor_events.h>

#include <osquery/utils/system/uptime.h>

namespace osquery {
FLAG(bool,
     audit_allow_apparmor_events,
     false,
     "Allow the publisher to process audit events");

REGISTER(AppArmorEventSubscriber, "event_subscriber", "apparmor_events");

Status AppArmorEventSubscriber::init() {
  if (!FLAGS_audit_allow_apparmor_events) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&AppArmorEventSubscriber::callback, sc);

  return Status();
}

Status AppArmorEventSubscriber::callback(const ECRef& ec, const SCRef& sc) {
  QueryData data;
  auto status = processEvents(data, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(data);

  return Status();
}

Status AppArmorEventSubscriber::processEvents(
    QueryData& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::AppArmor) {
      continue;
    }

    if (event.record_list.size() != 1) {
      VLOG(1) << "AppArmorEventSubscriber got record list";
      continue;
    }

    Row r;
    const auto& event_data = boost::get<AppArmorAuditEventData>(event.data);
    const auto& record = event.record_list[0];

    auto record_pretty_name_it = kAppArmorRecordLabels.find(record.type);
    if (record_pretty_name_it == kAppArmorRecordLabels.end()) {
      r["type"] = std::to_string(record.type);
    } else {
      r["type"] = record_pretty_name_it->second;
    }

    r["message"] = record.raw_data;
    r["uptime"] = std::to_string(getUptime());

    for (const auto& field : event_data.fields) {
      switch (field.second.which()) {
      case 0:
        // string field
        r[field.first] = boost::get<std::string>(field.second);
        break;
      case 1:
        r[field.first] =
            UNSIGNED_BIGINT(boost::get<const std::uint64_t>(field.second));
        break;
      default:
        continue;
      }
    }

    emitted_row_list.push_back(r);
  }

  return Status();
}

const std::set<int>& AppArmorEventSubscriber::getEventSet() noexcept {
  return kAppArmorEventSet;
}
} // namespace osquery
