/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/sql.h>

#include "osquery/core/conversions.h"
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
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  /// Socket events come in pairs, first the syscall then the structure.
  bool waiting_for_saddr_{false};

  /// The intermediate row structure.
  Row row_;
};

REGISTER(SocketEventSubscriber, "event_subscriber", "socket_events");

Status SocketEventSubscriber::init() {
  auto sc = createSubscriptionContext();

  // Monitor for bind and connect syscalls.
  sc->rules.push_back({AUDIT_SYSCALL_BIND, ""});
  sc->rules.push_back({AUDIT_SYSCALL_CONNECT, ""});
  // Also grab SADDR structures
  sc->types.insert(AUDIT_TYPE_SOCKADDR);

  // Drop events if they are encountered outside of the expected state.
  // sc->types = {AUDIT_SYSCALL};
  subscribe(&SocketEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

void parseSockAddr(const std::string& saddr, Row& r, bool local) {
  // The protocol is not included in the audit message.
  if (saddr[0] == '0' && saddr[1] == '2') {
    // IPv4
    r["family"] = "2";
    long result{0};
    safeStrtol(saddr.substr(4, 4), 16, result);
    r[(local) ? "local_port" : "remote_port"] = INTEGER(result);
    safeStrtol(saddr.substr(8, 8), 16, result);
    auto address = std::to_string((result & 0xff000000) >> 24) + "." +
                   std::to_string((result & 0x00ff0000) >> 16) + "." +
                   std::to_string((result & 0x0000ff00) >> 8) + "." +
                   std::to_string((result & 0x000000ff));
    r[(local) ? "local_address" : "remote_address"] = std::move(address);
  } else if (saddr[0] == '0' && saddr[1] == 'A') {
    // IPv6
    r["family"] = "11";
    long result{0};
    safeStrtol(saddr.substr(4, 4), 16, result);
    r[(local) ? "local_port" : "remote_port"] = INTEGER(result);
    std::string address;
    for (size_t i = 0; i < 8; ++i) {
      address += saddr.substr(16 + (i * 4), 4);
      if (i == 0 || i % 7 != 0) {
        address += ":";
      }
    }
    boost::algorithm::to_lower(address);
    r[(local) ? "local_address" : "remote_address"] = std::move(address);
  } else if (saddr[0] == '0' && saddr[1] == '1' && saddr.size() > 6) {
    // Unix domain
    r["family"] = "1";
    r["local_port"] = "0";
    r["remote_port"] = "0";
    off_t begin = (saddr[4] == '0' && saddr[5] == '0') ? 6 : 4;
    auto end = saddr.substr(begin).find("00");
    end = (end == std::string::npos) ? saddr.size() : end + 4;
    try {
      r["socket"] = boost::algorithm::unhex(saddr.substr(begin, end - begin));
    } catch (const boost::algorithm::hex_decode_error& e) {
      r["socket"] = "unknown";
    }
  } else {
    r["family"] = "-1";
    // No idea!
    r["local_address"] = "unknown";
    r["remote_address"] = "unknown";
  }
}

Status SocketEventSubscriber::Callback(const ECRef& ec, const SCRef&) {
  if (waiting_for_saddr_) {
    if (ec->type == AUDIT_TYPE_SOCKADDR) {
      auto& saddr = ec->fields["saddr"];
      if (saddr.size() < 4 || saddr[0] == '1') {
        return Status(0);
      }
      row_["protocol"] = "0";
      row_["local_port"] = "0";
      row_["remote_port"] = "0";
      // Parse the struct and emit the row.
      parseSockAddr(saddr, row_, (row_.at("action") == "bind"));
      add(row_, getUnixTime());
      Row().swap(row_);
      waiting_for_saddr_ = false;
    }
  } else if (ec->type != AUDIT_TYPE_SYSCALL) {
    return Status(0);
  }

  if (ec->syscall == AUDIT_SYSCALL_CONNECT) {
    // The connect syscall must exit with EINPROGRESS
    if (ec->fields.count("exit") && ec->fields.at("exit") != "-115") {
      return Status(0);
    }
    row_["action"] = "connect";
  } else if (ec->syscall == AUDIT_SYSCALL_BIND) {
    row_["action"] = "bind";
  } else {
    return Status(0);
  }

  row_["pid"] = ec->fields["pid"];
  row_["path"] = ec->fields["exe"];
  // TODO: This is a hex value.
  row_["fd"] = ec->fields["a0"];
  // The open/bind success status.
  row_["success"] = (ec->fields["success"] == "yes") ? "1" : "0";
  row_["uptime"] = BIGINT(tables::getUptime());
  waiting_for_saddr_ = true;
  return Status(0);
}
} // namespace osquery
