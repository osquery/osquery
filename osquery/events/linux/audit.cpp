/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/audit.h"

namespace osquery {

/// The audit subsystem may have a performance impact on the system.
FLAG(bool,
     disable_audit,
     true,
     "Disable receiving events from the audit subsystem");

/// Control the audit subsystem by electing to be the single process sink.
FLAG(bool, audit_persist, true, "Attempt to retain control of audit");

/// Control the audit subsystem by allowing subscriptions to apply rules.
FLAG(bool,
     audit_allow_config,
     false,
     "Allow the audit publisher to change auditing configuration");

REGISTER(AuditEventPublisher, "event_publisher", "audit");

enum AuditStatus {
  AUDIT_DISABLED = 0,
  AUDIT_ENABLED = 1,
  AUDIT_IMMUTABLE = 2,
};

static const int kAuditMLatency = 1000;

Status AuditEventPublisher::setUp() {
  handle_ = audit_open();
  if (handle_ <= 0) {
    // Could not open the audit subsystem.
    return Status(1, "Could not open audit subsystem");
  }

  // The setup can try to enable auditing.
  if (!FLAGS_disable_audit && FLAGS_audit_allow_config) {
    audit_set_enabled(handle_, AUDIT_ENABLED);
  }

  auto enabled = audit_is_enabled(handle_);
  if (enabled == AUDIT_IMMUTABLE || getuid() != 0 ||
      !FLAGS_audit_allow_config) {
    // The audit subsystem is in an immutable mode.
    immutable_ = true;
  } else if (enabled != AUDIT_ENABLED) {
    // No audit subsystem is available, or an error was encountered.
    audit_close(handle_);
    return Status(1, "Audit subsystem is not enabled");
  }

  // The auditd daemon sets its PID.
  if (!FLAGS_disable_audit && !immutable_) {
    if (audit_set_pid(handle_, getpid(), WAIT_YES) < 0) {
      // Could not set our process as the userspace auditing daemon.
      return Status(1, "Could not set audit PID");
    }
    // This process is now in control of audit.
    control_ = true;

    // Want to set a min sane buffer and maximum number of events/second min.
    // This is normally controlled through the audit config, but we must
    // enforce sane minimums: -b 8192 -e 100

    // Request only the highest priority of audit status messages.
    set_aumessage_mode(MSG_QUIET, DBG_NO);
  }
  return Status(0, "OK");
}

void AuditEventPublisher::configure() {
  // Able to issue libaudit API calls.
  struct AuditRuleInternal rule;

  // Before reply data is ever filled in, assure an empty message.
  memset(&reply_, 0, sizeof(struct audit_reply));

  if (handle_ <= 0 || FLAGS_disable_audit || immutable_) {
    // No configuration or rule manipulation needed.
    // The publisher run loop may still receive audit metadata events.
    return;
  }

  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    for (const auto& scr : sc->rules) {
      // Reset all members to nothing.
      memset(&rule.rule, 0, sizeof(struct audit_rule_data));

      if (scr.syscall != 0) {
        audit_rule_syscall_data(&rule.rule, scr.syscall);
      }

      if (scr.filter.size() > 0) {
        // Fill in rule's filter data.
        auto* rrule = &rule.rule;
        audit_rule_fieldpair_data(&rrule, scr.filter.c_str(), scr.flags);
      }

      // Apply this rule to the EXIT filter, ALWAYS.
      int rc = audit_add_rule_data(handle_, &rule.rule, scr.flags, scr.action);
      if (rc < 0) {
        // Problem adding rule. If errno == EEXIST then fine.
        VLOG(1) << "Cannot add audit rule: syscall=" << scr.syscall
                << " filter='" << scr.filter << "': error " << rc;
      }

      // Note: all rules are considered transient if added by subscribers.
      // Add this rule data to the publisher's list of transient rules.
      // These will be removed during tear down or re-configure.
      rule.flags = scr.flags;
      rule.action = scr.action;
      transient_rules_.push_back(rule);
    }
  }

  // The audit library provides an API to send a netlink request that fills in
  // a netlink reply with audit rules. As such, this process will maintain a
  // single open handle and reply to audit-metadata tables with the buffered
  // content from the publisher.
  if (audit_request_rules_list_data(handle_) <= 0) {
    // Could not request audit rules.
  }
}

void AuditEventPublisher::tearDown() {
  if (handle_ <= 0) {
    return;
  }

  // The configure step will store successful rule adds.
  // Each of these rules has been added by the publisher and should be remove
  // when the process tears down.
  if (!immutable_) {
    for (auto& rule : transient_rules_) {
      audit_delete_rule_data(handle_, &rule.rule, rule.flags, rule.action);
    }
  }

  audit_close(handle_);
}

inline void handleAuditConfigChange(const struct audit_reply& reply) {
  // Another daemon may have taken control.
}

inline bool handleAuditReply(const struct audit_reply& reply,
                             AuditEventContextRef& ec) {
  // Build an event context around this reply.
  ec->type = reply.type;

  // Tokenize the message.
  auto message = std::string(reply.message, reply.len);
  auto preamble_end = message.find("): ");
  if (preamble_end == std::string::npos) {
    return false;
  } else {
    ec->preamble = message.substr(0, preamble_end + 1);
    message = message.substr(preamble_end + 3);
  }

  // The linear search will construct series of key value pairs.
  std::string key, value;
  // There are several ways of representing value data (enclosed strings, etc).
  bool found_assignment{false}, found_enclose{false};
  for (const auto& c : message) {
    // Iterate over each character in the audit message.
    if ((found_enclose && c == '"') || (!found_enclose && c == ' ')) {
      if (c == '"') {
        value += c;
      }
      // This is a terminating sequence, the end of an enclosure or space tok.
      if (!key.empty()) {
        // Multiple space tokens are supported.
        ec->fields[key] = value;
      }
      found_enclose = false;
      found_assignment = false;
      key.clear();
      value.clear();
    } else if (!found_assignment && c == ' ') {
      // A field tokenizer.
    } else if (found_assignment) {
      // Enclosure sequences appear immediately following assignment.
      if (c == '"') {
        found_enclose = true;
      }
      value += c;
    } else if (c == '=') {
      found_assignment = true;
    } else {
      key += c;
    }
  }

  // Last step, if there was no trailing tokenizer.
  if (!key.empty()) {
    ec->fields[key] = value;
  }

  // There is a special field for syscalls.
  if (ec->fields.count("syscall") == 1) {
    const auto& syscall_string = ec->fields.at("syscall").c_str();
    long long syscall{0};
    if (!safeStrtoll(syscall_string, 10, syscall)) {
      syscall = 0;
    }
    ec->syscall = syscall;
  }

  return true;
}

void AuditEventPublisher::handleListRules() {
  // Store the rules response.
  // This is not needed until there are audit meta-tables listing the rules.
}

Status AuditEventPublisher::run() {
  if (!FLAGS_disable_audit && (count_ == 0 || count_++ % 10 == 0)) {
    // Request an update to the audit status.
    // This will also fill in the status on first run.
    audit_request_status(handle_);
  }

  // Reset the reply data.
  int result = 0;
  bool handle_reply = false;
  while (true) {
    handle_reply = false;

    // Request a reply in a non-blocking mode.
    // This allows the publisher's run loop to periodically request an audit
    // status update. These updates can check for other processes attempting to
    // gain control over the audit sink.
    // This non-blocking also allows faster receipt of multi-message events.
    result = audit_get_reply(handle_, &reply_, GET_REPLY_NONBLOCKING, 0);
    if (result > 0) {
      switch (reply_.type) {
      case NLMSG_NOOP:
      case NLMSG_DONE:
      case NLMSG_ERROR:
        // Not handled, request another reply.
        break;
      case AUDIT_LIST_RULES:
        // Build rules cache.
        handleListRules();
        break;
      case AUDIT_GET:
        // Make a copy of the status reply and store as the most-recent.
        if (reply_.status != nullptr) {
          memcpy(&status_, reply_.status, sizeof(struct audit_status));
        }
        break;
      case AUDIT_FIRST_USER_MSG... AUDIT_LAST_USER_MSG:
        handle_reply = true;
        break;
      case (AUDIT_GET + 1)...(AUDIT_LIST_RULES - 1):
      case (AUDIT_LIST_RULES + 1)...(AUDIT_FIRST_USER_MSG - 1):
        // Not interested in handling meta-commands and actions.
        break;
      case AUDIT_DAEMON_START... AUDIT_DAEMON_CONFIG: // 1200 - 1203
      case AUDIT_CONFIG_CHANGE:
        handleAuditConfigChange(reply_);
        break;
      case AUDIT_SYSCALL: // 1300
        // A monitored syscall was issued, most likely part of a multi-record.
        handle_reply = true;
        break;
      case AUDIT_CWD: // 1307
      case AUDIT_PATH: // 1302
      case AUDIT_EXECVE: // // 1309 (execve arguments).
        handle_reply = true;
      case AUDIT_EOE: // 1320 (multi-record event).
        break;
      default:
        // All other cases, pass to reply.
        handle_reply = true;
      }
    } else {
      // Fall through to the run loop cool down.
      break;
    }

    // Replies are 'handled' as potential events for several audit types.
    if (handle_reply) {
      auto ec = createEventContext();
      // Build the event context from the reply type and parse the message.
      if (handleAuditReply(reply_, ec)) {
        fire(ec);
      }
    }
  }

  if (static_cast<pid_t>(status_.pid) != getpid()) {
    if (control_ && status_.pid != 0) {
      VLOG(1) << "Audit control lost to pid: " << status_.pid;
      // This process has lost control of audit.
      // The initial request for control was made during setup.
      control_ = false;
    }

    if (FLAGS_audit_persist && !FLAGS_disable_audit && !immutable_) {
      VLOG(1) << "Persisting audit control";
      audit_set_pid(handle_, getpid(), WAIT_NO);
      control_ = true;
    }
  }

  // Only apply a cool down if the reply request failed.
  osquery::publisherSleep(kAuditMLatency);
  return Status(0, "OK");
}

bool AuditEventPublisher::shouldFire(const AuditSubscriptionContextRef& sc,
                                     const AuditEventContextRef& ec) const {
  // User messages allow a catch all configuration.
  if (sc->user_types &&
      (ec->type >= AUDIT_FIRST_USER_MSG && ec->type <= AUDIT_LAST_USER_MSG)) {
    return true;
  }

  // If this subscription (with set of rules) explicitly requested the audit
  // reply type.
  for (const auto& type : sc->types) {
    if (type != 0 && ec->type == type) {
      return true;
    }
  }

  // Otherwise, if the set of rules included a syscall, match on that number.
  for (const auto& rule : sc->rules) {
    if (rule.syscall != 0 && ec->syscall == rule.syscall) {
      return true;
    }
  }

  return false;
}
}
