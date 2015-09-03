/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <set>
#include <vector>

#include <libaudit.h>

#include <osquery/events.h>

namespace osquery {

/**
 * @brief A simple audit rule description that can be populated via a config.
 *
 * Allow a config definition to set an integer syscall or string-format filters
 * that can be iterated and transformed into libaudit rules.
 *
 * The libaudit rules are only applied if `apply_rule` is set to true.
 */
struct AuditRule {
  /// The rule may either contain a filter or syscall number.
  int syscall{0};

  /// The rule may either contain a filter or a syscall number.
  std::string filter;

  /// All rules must include an action and set of flags.
  int flags{AUDIT_FILTER_EXIT};
  int action{AUDIT_ALWAYS};

  /// Audit rules are used for matching events to subscribers.
  /// They can also apply their syscall or filter rule during setUp.
  bool apply_rule{true};

  /// Helper to set either a syscall, filter, or both.
  AuditRule(int _syscall, std::string _filter)
      : syscall(_syscall), filter(std::move(_filter)) {}
};

/// Internal rule storage for transient rule additions/removals.
struct AuditRuleInternal {
  struct audit_rule_data rule;
  int flags{0};
  int action{0};
};

/**
 * @brief Audit will generate consecutive messages related to a process event.
 *
 * The first are the syscall details, which contain information about the
 * process generating the event. That is followed by the exec arguments
 * including the canonicalized/interpreted program name. The working directory
 * and a null-delimited set of path messages follow and complete the set of
 * information.
 */
enum AuditProcessEventState {
  STATE_SYSCALL = AUDIT_SYSCALL,
  STATE_EXECVE = AUDIT_EXECVE,
  STATE_CWD = AUDIT_CWD,
  STATE_PATH = AUDIT_PATH,
};

struct AuditSubscriptionContext : public SubscriptionContext {
  /**
   * @brief A subscription may supply a set of rules.
   *
   * These are audit rules that include syscalls to monitor or filters to
   * append. This set of rules is added to the system-configured audit rule set.
   * All rules are removed when the audit publisher is torn down.
   */
  std::vector<AuditRule> rules;

  /**
   * @brief Independent of the rules, supply a set of reply types used to fire.
   *
   * Matching a rule does not mean the subscription callback will fire.
   * If any of the rules included a syscall then an audit type=SYSCALL for that
   * syscall will fire. Otherwise a subscription should include the set of audit
   * reply types it handles.
   */
  std::set<int> types;

 private:
  friend class AuditEventPublisher;
};

struct AuditEventContext : public EventContext {
  /// The audit reply type.
  int type{0};

  /// If the type=AUDIT_SYSCALL then this is filled in with the syscall type.
  /// Otherwise this set to 0.
  int syscall{0};

  /**
   * @brief The audit message tokenized into fields.
   *
   * If the field contained a space in the value the data will be hex encoded.
   * It is the responsibility of the subscription callback/handler to parse.
   */
  std::map<std::string, std::string> fields;

  /// Each message will contain the audit time.
  std::string preamble;
};

typedef std::shared_ptr<AuditEventContext> AuditEventContextRef;
typedef std::shared_ptr<AuditSubscriptionContext> AuditSubscriptionContextRef;

class AuditEventPublisher
    : public EventPublisher<AuditSubscriptionContext, AuditEventContext> {
  DECLARE_PUBLISHER("audit");

 public:
  /**
   * @brief Set up the process/thread for handling audit netlink replies.
   *
   * This will try to open an audit netlink descriptor. If the netlink handle
   * is opened the process will check if auditing is enabled, and attempt to
   * gain control of audit message sinks (replies). This requires root
   * credentials and will have an impact on system performance.
   *
   * An 'auditd'-like process cannot (or should not) be running in tandem. Only
   * one process may receive audit messages from the audit kernel thread over
   * the netlink API. However, multiple processes may open a handle and send
   * audit requests. If an 'auditd'-like process starts while osquery is
   * receiving audit messages, this process may optionally 'regain' or attempt
   * to persist auditing capabilities by reseting the audit reply handle
   * ownership to itself.
   *
   * See the `--audit-persist` command line option.
   */
  Status setUp();

  /// Fill in audit rules based on syscall/filter combinations.
  void configure();

  /// Remove audit rules and close the handle.
  void tearDown();

  /// Poll for replies to the netlink handle in a non-blocking mode.
  Status run();

  AuditEventPublisher() : EventPublisher() {}

 private:
  /// Maintain a list of audit rule data for displaying or deleting.
  void handleListRules();

  /// Apply normal subscription to event matching logic.
  bool shouldFire(const AuditSubscriptionContextRef& mc,
                  const AuditEventContextRef& ec) const;

 private:
  /// Audit subsystem (netlink) socket descriptor.
  int handle_{0};

  /// Audit subsystem is in an immutable state.
  bool immutable_{false};

  /**
   * @brief The last (most current) status reply.
   *
   * This contains the: pid, enabled, rate_limit, backlog_limit, lost, and
   * failure booleans and counts.
   */
  struct audit_status status_;

  /**
   * @brief A counter of non-blocking netlink reads that contained no data.
   *
   * After several iterations of no data, the audit run loop will request a
   * status. It is possible another user land daemon requested control of the
   * audit subsystem. The kernel thread will only emit to a single handle.
   */
  size_t count_{0};

  /// Is this process in control of the audit subsystem.
  bool control_{false};

  /// The last (most recent) audit reply.
  struct audit_reply reply_;

  /// Track all rule data added by the publisher.
  std::vector<struct AuditRuleInternal> transient_rules_;
};
}
