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

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/events/linux/audit.h"

namespace osquery {

#define AUDIT_SYSCALL_EXECVE 59

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

class ProcessEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  /// The next expected process event state.
  AuditProcessEventState state_{STATE_SYSCALL};

  /// Along with the state, track the building row.
  Row row_;
};

inline std::string decodeAuditValue(const std::string& s) {
  if (s.size() > 1 && s[0] == '"') {
    return s.substr(1, s.size() - 2);
  }
  try {
    return boost::algorithm::unhex(s);
  } catch (const boost::algorithm::hex_decode_error& e) {
    return s;
  }
}

Status validAuditState(int type, AuditProcessEventState& state) {
  // Define some acceptable transitions outside of the default state.
  bool acceptable = (type == STATE_PATH && state == STATE_EXECVE);
  acceptable |= (type == STATE_PATH && state == STATE_CWD);
  if (type != state && !acceptable) {
    // This is an out-of-order event, drop it.
    return Status(1, "Out of order");
  }

  // Update the next expected state.
  if (type == AUDIT_SYSCALL) {
    state = STATE_EXECVE;
  } else if (type == AUDIT_EXECVE) {
    state = STATE_CWD;
  } else if (type == AUDIT_CWD) {
    state = STATE_PATH;
  } else {
    state = STATE_SYSCALL;
  }

  return Status(0, "OK");
}

inline void updateAuditRow(const AuditEventContextRef& ec, Row& r) {
  const auto& fields = ec->fields;
  if (ec->type == AUDIT_SYSCALL) {
    r["pid"] = (fields.count("pid")) ? fields.at("pid") : "0";
    r["parent"] = fields.count("ppid") ? fields.at("ppid") : "0";
    r["uid"] = fields.count("uid") ? fields.at("uid") : "0";
    r["euid"] = fields.count("euid") ? fields.at("euid") : "0";
    r["gid"] = fields.count("gid") ? fields.at("gid") : "0";
    r["egid"] = fields.count("egid") ? fields.at("euid") : "0";
    r["path"] = (fields.count("exe")) ? decodeAuditValue(fields.at("exe")) : "";

    // This should get overwritten during the EXECVE state.
    r["cmdline"] = (fields.count("comm")) ? fields.at("comm") : "";
    // Do not record a cmdline size. If the final state is reached and no 'argc'
    // has been filled in then the EXECVE state was not used.
    r["cmdline_size"] = "";

    r["overflows"] = "";
    r["env_size"] = "0";
    r["env_count"] = "0";
    r["env"] = "";
  }

  if (ec->type == AUDIT_EXECVE) {
    // Reset the temporary storage from the SYSCALL state.
    r["cmdline"] = "";
    for (const auto& arg : fields) {
      if (arg.first == "argc") {
        continue;
      }

      // Amalgamate all the "arg*" fields.
      if (r.at("cmdline").size() > 0) {
        r["cmdline"] += " ";
      }
      r["cmdline"] += decodeAuditValue(arg.second);
    }

    // There may be a better way to calculate actual size from audit.
    // Then an overflow could be calculated/determined based on actual/expected.
    r["cmdline_size"] = std::to_string(r.at("cmdline").size());
  }

  if (ec->type == AUDIT_PATH) {
    r["mode"] = (fields.count("mode")) ? fields.at("mode") : "";
    r["owner_uid"] = fields.count("ouid") ? fields.at("ouid") : "0";
    r["owner_gid"] = fields.count("ogid") ? fields.at("ogid") : "0";

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, r.at("path"));
    if (qd.size() == 1) {
      r["ctime"] = qd.front().at("ctime");
      r["atime"] = qd.front().at("atime");
      r["mtime"] = qd.front().at("mtime");
      r["btime"] = "0";
    }

    // Uptime is helpful for execution-based events.
    r["uptime"] = std::to_string(tables::getUptime());
  }
}

REGISTER(ProcessEventSubscriber, "event_subscriber", "process_events");

Status ProcessEventSubscriber::init() {
  auto sc = createSubscriptionContext();

  // Monitor for execve syscalls.
  sc->rules.push_back({AUDIT_SYSCALL_EXECVE, ""});

  // Request call backs for all parts of the process execution state.
  // Drop events if they are encountered outside of the expected state.
  sc->types = {AUDIT_SYSCALL, AUDIT_EXECVE, AUDIT_CWD, AUDIT_PATH};
  subscribe(&ProcessEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status ProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  // Check and set the valid state change.
  // If this is an unacceptable change reset the state and clear row data.
  if (ec->fields.count("success") && ec->fields.at("success") == "no") {
    return Status(0, "OK");
  }

  if (!validAuditState(ec->type, state_).ok()) {
    state_ = STATE_SYSCALL;
    Row().swap(row_);
    return Status(0, "OK");
  }

  // Fill in row fields based on the event state.
  updateAuditRow(ec, row_);

  // Only add the event if finished (aka a PATH event was emitted).
  if (state_ == STATE_SYSCALL) {
    // If the EXECVE state was not used, decode the cmdline value.
    if (row_.at("cmdline_size").size() == 0) {
      // This allows at most 1 decode call per potentially-encoded item.
      row_["cmdline"] = decodeAuditValue(row_.at("cmdline"));
      row_["cmdline_size"] = "1";
    }

    add(row_);
    Row().swap(row_);
  }

  return Status(0, "OK");
}
} // namespace osquery
