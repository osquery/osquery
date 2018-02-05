/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/events/linux/audit.h"

#define DECLARE_TABLE_IMPLEMENTATION_user_events
#include <generated/tables/tbl_user_events_defs.hpp>

namespace osquery {

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

// From process_events.
extern std::string decodeAuditValue(const std::string& s);

class UserEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The user event subscriber declares an audit event type subscription.
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(UserEventSubscriber, "event_subscriber", "user_events");

Status UserEventSubscriber::init() {
  auto sc = createSubscriptionContext();

  // Request call backs for all user-related auditd events.
  sc->user_types = true;
  subscribe(&UserEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status UserEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  r["uid"] = ec->fields["uid"];
  r["pid"] = ec->fields["pid"];
  if (ec->fields.count("msg") && ec->fields.at("msg").size() > 1) {
    ec->fields["msg"].erase(0, 1);
    r["message"] = std::move(ec->fields["msg"]);
  }
  r["auid"] = ec->fields["auid"];
  r["type"] = INTEGER(ec->type);
  r["path"] = decodeAuditValue(ec->fields["exe"]);
  r["address"] = ec->fields["addr"];
  r["terminal"] = ec->fields["terminal"];
  r["uptime"] = INTEGER(tables::getUptime());

  add(r);
  return Status(0, "OK");
}
} // namespace osquery
