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

namespace {
// clang-format off
// This map must contain exactly the same elements that
// SELinuxEventSubscriber::GetEventSet() returns!
const std::map<int, std::string> record_type_to_label = {
  {AUDIT_USER_AVC, "USER_AVC"},
  {AUDIT_AVC, "AVC"},
  {AUDIT_SELINUX_ERR, "SELINUX_ERR"},
  {AUDIT_AVC_PATH, "AVC_PATH"},
  {AUDIT_MAC_POLICY_LOAD, "MAC_POLICY_LOAD"},
  {AUDIT_MAC_STATUS, "MAC_STATUS"},
  {AUDIT_MAC_CONFIG_CHANGE, "MAC_CONFIG_CHANGE"},
  {AUDIT_MAC_UNLBL_ALLOW, "MAC_UNLBL_ALLOW"},
  {AUDIT_MAC_CIPSOV4_ADD, "MAC_CIPSOV4_ADD"},
  {AUDIT_MAC_CIPSOV4_DEL, "MAC_CIPSOV4_DEL"},
  {AUDIT_MAC_MAP_ADD, "MAC_MAP_ADD"},
  {AUDIT_MAC_MAP_DEL, "MAC_MAP_DEL"},
  {AUDIT_MAC_IPSEC_ADDSA, "MAC_IPSEC_ADDSA"},
  {AUDIT_MAC_IPSEC_DELSA, "MAC_IPSEC_DELSA"},
  {AUDIT_MAC_IPSEC_ADDSPD, "MAC_IPSEC_ADDSPD"},
  {AUDIT_MAC_IPSEC_DELSPD, "MAC_IPSEC_DELSPD"},
  {AUDIT_MAC_IPSEC_EVENT, "MAC_IPSEC_EVENT"},
  {AUDIT_MAC_UNLBL_STCADD, "MAC_UNLBL_STCADD"},
  {AUDIT_MAC_UNLBL_STCDEL, "MAC_UNLBL_STCDEL"}
};
// clang-format on
} // namespace

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

      r["type"] = record_type_to_label.at(record.type);
      r["msg"] = record.raw_data;
      r["uptime"] = std::to_string(tables::getUptime());
      emitted_row_list.push_back(r);
    }
  }

  return Status(0, "Ok");
}

const std::set<int>& SELinuxEventSubscriber::GetEventSet() noexcept {
  // Documented events that could not be found in the headers:
  // - USER_SELINUX_ERR
  // - USER_MAC_POLICY_LOAD
  // - USER_ROLE_CHANGE
  // - USER_LABEL_EXPORT
  static const std::set<int> selinux_event_list = {
      // This is outside the documented numeric range (1400-1499)
      AUDIT_USER_AVC,

      AUDIT_AVC,
      AUDIT_SELINUX_ERR,
      AUDIT_AVC_PATH,
      AUDIT_MAC_POLICY_LOAD,
      AUDIT_MAC_STATUS,
      AUDIT_MAC_CONFIG_CHANGE,
      AUDIT_MAC_UNLBL_ALLOW,
      AUDIT_MAC_CIPSOV4_ADD,
      AUDIT_MAC_CIPSOV4_DEL,
      AUDIT_MAC_MAP_ADD,
      AUDIT_MAC_MAP_DEL,
      AUDIT_MAC_IPSEC_ADDSA,
      AUDIT_MAC_IPSEC_DELSA,
      AUDIT_MAC_IPSEC_ADDSPD,
      AUDIT_MAC_IPSEC_DELSPD,
      AUDIT_MAC_IPSEC_EVENT,
      AUDIT_MAC_UNLBL_STCADD,
      AUDIT_MAC_UNLBL_STCDEL};

  return selinux_event_list;
}
} // namespace osquery
