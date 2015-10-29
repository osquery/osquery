/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/sql.h>

#include "osquery/events/linux/audit.h"

namespace osquery {

#define AUDIT_SYSCALL_BIND 49
#define AUDIT_SYSCALL_CONNECT 42

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

class SocketEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// Decorating syscall events with socket information on Linux is expensive.
  SocketEventSubscriber() : EventSubscriber(false) {}

  /// The process event subscriber declares an audit event type subscription.
  Status init();

  /// Kernel events matching the event type will fire.
  Status Callback(const AuditEventContextRef& ec, const void* user_data);
};

REGISTER(SocketEventSubscriber, "event_subscriber", "socket_events");

Status SocketEventSubscriber::init() {
  auto sc = createSubscriptionContext();

  // Monitor for bind and connect syscalls.
  sc->rules.push_back({AUDIT_SYSCALL_BIND, ""});
  sc->rules.push_back({AUDIT_SYSCALL_CONNECT, ""});

  // Drop events if they are encountered outside of the expected state.
  // sc->types = {AUDIT_SYSCALL};
  subscribe(&SocketEventSubscriber::Callback, sc, nullptr);

  return Status(0, "OK");
}

Status SocketEventSubscriber::Callback(const AuditEventContextRef& ec,
                                       const void* user_data) {
  Row r;
  r["pid"] = ec->fields["pid"];
  r["path"] = ec->fields["exe"];
  r["fd"] = ec->fields["a0"];

  if (ec->syscall == AUDIT_SYSCALL_CONNECT) {
    r["action"] = "connect";
    // The connect syscall must exit with EINPROGRESS
    if (ec->fields.count("exit") && ec->fields.at("exit") != "-115") {
      return Status(0, "Not recording socket event");
    }

  } else if (ec->syscall == AUDIT_SYSCALL_BIND) {
    r["action"] = "bind";
  }

  // The open/bind success status.
  r["success"] = (ec->fields["success"] == "yes") ? "1" : "0";

  auto qd = SQL::selectAllFrom("process_open_sockets", "pid", EQUALS, r["pid"]);
  for (const auto& row : qd) {
    if (row.at("fd") == r["fd"]) {
      // For the socket event that happens before a bind.
      if (row.at("socket").empty()) {
        return Status(0, "No socket information");
      }

      r["socket"] = row.at("socket");
      r["family"] = row.at("family");
      r["protocol"] = row.at("protocol");
      r["remote_address"] = row.at("remote_address");
      r["local_address"] = row.at("local_address");
      r["remote_port"] = row.at("remote_port");
      r["local_port"] = row.at("local_port");
      break;
    }
  }

  if (r.count("socket") == 0) {
    return Status(0, "No socket found");
  }

  r["uptime"] = std::to_string(tables::getUptime());
  add(r, getUnixTime());
  return Status(0, "OK");
}
} // namespace osquery
