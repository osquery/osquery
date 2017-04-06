/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/audit.h"

namespace osquery {

#define AUDIT_SYSCALL_BIND 49
#define AUDIT_SYSCALL_CONNECT 42

FLAG(bool,
     audit_allow_sockets,
     false,
     "Allow the audit publisher to install socket-related rules");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

class SocketEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// This subscriber depends on a configuration boolean.
  Status setUp() override {
    if (!FLAGS_audit_allow_sockets) {
      return Status(1, "Subscriber disabled via configuration");
    }
    return Status(0);
  }

  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  AuditAssembler asm_;
};

REGISTER(SocketEventSubscriber, "event_subscriber", "socket_events");

inline std::string ip4FromSaddr(const std::string& saddr, ushort offset) {
  long result{0};
  safeStrtol(saddr.substr(offset, 8), 16, result);
  return std::to_string((result & 0xff000000) >> 24) + "." +
         std::to_string((result & 0x00ff0000) >> 16) + "." +
         std::to_string((result & 0x0000ff00) >> 8) + "." +
         std::to_string((result & 0x000000ff));
}

void parseSockAddr(const std::string& saddr, AuditFields& r) {
  // The protocol is not included in the audit message.
  if (saddr[0] == '0' && saddr[1] == '2') {
    // IPv4
    r["family"] = "2";
    long result{0};
    safeStrtol(saddr.substr(4, 4), 16, result);
    r["remote_port"] = INTEGER(result);
    r["remote_address"] = ip4FromSaddr(saddr, 8);
  } else if (saddr[0] == '0' && saddr[1] == 'A') {
    // IPv6
    r["family"] = "11";
    long result{0};
    safeStrtol(saddr.substr(4, 4), 16, result);
    r["remote_port"] = INTEGER(result);
    std::string address;
    for (size_t i = 0; i < 8; ++i) {
      address += saddr.substr(16 + (i * 4), 4);
      if (i == 0 || i % 7 != 0) {
        address += ":";
      }
    }
    boost::algorithm::to_lower(address);
    r["remote_address"] = std::move(address);
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

bool SocketUpdate(size_t type, const AuditFields& fields, AuditFields& r) {
  if (type == AUDIT_TYPE_SOCKADDR) {
    const auto& saddr = fields.at("saddr");
    if (saddr.size() < 4 || saddr[0] == '1') {
      return false;
    }

    r["protocol"] = "0";
    r["local_port"] = "0";
    r["remote_port"] = "0";
    // Parse the struct and emit the row.
    parseSockAddr(saddr, r);
    return true;
  }

  r["auid"] = fields.at("auid");
  r["pid"] = fields.at("pid");
  r["path"] = decodeAuditValue(fields.at("exe"));
  // TODO: This is a hex value.
  r["fd"] = fields.at("a0");
  // The open/bind success status.
  r["success"] = (fields.at("success") == "yes") ? "1" : "0";
  r["uptime"] = std::to_string(tables::getUptime());
  return true;
}

Status SocketEventSubscriber::init() {
  asm_.start(10, {AUDIT_TYPE_SYSCALL, AUDIT_TYPE_SOCKADDR}, &SocketUpdate);

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

Status SocketEventSubscriber::Callback(const ECRef& ec, const SCRef&) {
  if (ec->syscall == AUDIT_SYSCALL_CONNECT) {
    if (ec->fields.count("exit") && ec->fields.at("exit") != "-115") {
      // The connect syscall may want an exit with EINPROGRESS.
    }
  } else if (ec->type == AUDIT_TYPE_SYSCALL &&
             ec->syscall != AUDIT_SYSCALL_BIND) {
    return Status(0);
  }

  auto fields = asm_.add(ec->audit_id, ec->type, ec->fields);
  if (ec->syscall == AUDIT_SYSCALL_CONNECT) {
    asm_.set(ec->audit_id, "action", "connect");
  } else if (ec->syscall == AUDIT_SYSCALL_BIND) {
    asm_.set(ec->audit_id, "action", "bind");
  }

  if (fields.is_initialized()) {
    if ((*fields)["action"] == "bind") {
      (*fields)["local_port"] = std::move((*fields)["remote_port"]);
      (*fields)["local_address"] = std::move((*fields)["remote_address"]);
    }
    add(*fields);
  }

  return Status(0);
}
} // namespace osquery
