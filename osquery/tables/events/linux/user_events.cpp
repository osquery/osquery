/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/events/linux/audit.h"

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
  Status init();

  Status Callback(const AuditEventContextRef& ec, const void* user_data);
};

REGISTER(UserEventSubscriber, "event_subscriber", "user_events");

Status UserEventSubscriber::init() {
  auto sc = createSubscriptionContext();

  // Request call backs for all user-related auditd events.
  sc->user_types = true;
  subscribe(&UserEventSubscriber::Callback, sc, nullptr);

  return Status(0, "OK");
}

Status UserEventSubscriber::Callback(const AuditEventContextRef& ec,
                                     const void* user_data) {
  Row r;
  r["uid"] = ec->fields["uid"];
  r["pid"] = ec->fields["pid"];
  r["message"] = ec->fields["msg"];
  r["type"] = INTEGER(ec->type);
  r["path"] = decodeAuditValue(ec->fields["exe"]);
  r["address"] = ec->fields["addr"];
  r["terminal"] = ec->fields["terminal"];
  r["uptime"] = INTEGER(tables::getUptime());

  add(r, getUnixTime());
  return Status(0, "OK");
}
} // namespace osquery
