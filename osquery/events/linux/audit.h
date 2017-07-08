/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <libaudit.h>

#include <atomic>
#include <future>
#include <map>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include <boost/algorithm/hex.hpp>
#include <boost/scoped_ptr.hpp>

#include <osquery/events.h>

#include "osquery/events/linux/auditnetlink.h"

namespace osquery {

#define AUDIT_TYPE_SYSCALL 1300
#define AUDIT_TYPE_SOCKADDR 1306

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

  /// The rule action.
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

/// Alias the field container so we can replace and improve with refactors.
using AuditFields = std::map<std::string, std::string>;

/**
 * @brief The message callback method used within AuditAssembler.
 *
 * When a subscriber requires multiple audit messages it will call %start on
 * an AuditAssembler. That subscriber must provide a callable AuditUpdate to
 * move message content from the single message line into the assembler's
 * row data.
 *
 * @param type The audit message type.
 * @param fields The current message's fields.
 * @param r The persistent row data.
 * @return true if the message was parsed correctly, false if the multi-message
 *   encountered an error and should be removed.
 */
using AuditUpdate =
    std::function<bool(size_t type, const AuditFields& fields, AuditFields& r)>;

/**
 * @brief A multi-message assembler based on expectations of message-type sets.
 *
 * Event publshers based on audit that expect to receive more than one message
 * in order to construct a single row must used an assbler. This will transact
 * several message types into a single set of fields.
 *
 * The publisher determines an acceptable queue size (the max number of)
 * concurrent audit IDs to maintain. It then defines a set of expected types
 * where when an ID has seen one of each the message is complete.
 *
 * The publisher also sets an update callable to transfer needed fields from
 * the audit message into a persisent Row.
 */
class AuditAssembler : private boost::noncopyable {
 public:
  /// Start or restart the message assembler.
  void start(size_t capacity, std::vector<size_t> types, AuditUpdate update);

  /// Add a message from audit.
  boost::optional<AuditFields> add(const std::string &id,
                                   size_t type,
                                   const AuditFields& fields);

  /// Allow the publisher to explicit-set fields.
  void set(const std::string &id, const std::string& key, const std::string& value) {
    m_[id][key] = value;
  }

  /// Remove an audit ID from the queue and clear associated messages/types.
  void evict(const std::string &id);

  /// Shuffle an audit ID to the front of the queue.
  void shuffle(const std::string & id);

  /// Check if the audit ID has completed each required message types.
  bool complete(const std::string & id);

 private:
  /// A map of audit ID to aggregate message fields.
  std::unordered_map<std::string, AuditFields> m_;

  /// A map of audit ID to current set of types seen.
  std::unordered_map<std::string, std::vector<size_t>> mt_;

  /// A functional callable to sanitize individual messages.
  AuditUpdate update_{nullptr};

  /// The queue size.
  size_t capacity_{0};

  /// The in-order (by time) queue of audit IDs.
  std::vector<std::string> queue_;

  /// The set of required types.
  std::vector<size_t> types_;

 private:
  FRIEND_TEST(AuditTests, test_audit_assembler);
};

/// Handle quote and hex-encoded audit field content.
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

  /// Macro for all types related to user messages.
  bool user_types{false};

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
  AuditFields fields;

  /// Each message will contain the audit ID.
  std::string audit_id{0};

  /// Each message will contain the event time.
  size_t time{0};
};

using AuditEventContextRef = std::shared_ptr<AuditEventContext>;
using AuditSubscriptionContextRef = std::shared_ptr<AuditSubscriptionContext>;

/// This is a dispatched service that handles published audit replies.
class AuditConsumerRunner;

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
  Status setUp() override;

  /// Fill in audit rules based on syscall/filter combinations.
  void configure() override;

  /// Remove audit rules and close the handle.
  void tearDown() override;

  /// Poll for replies to the netlink handle in a non-blocking mode.
  Status run() override;

 public:
  AuditEventPublisher() : EventPublisher() {}

  virtual ~AuditEventPublisher() {
    tearDown();
  }

 private:
  /// Apply normal subscription to event matching logic.
  bool shouldFire(const AuditSubscriptionContextRef& mc,
                  const AuditEventContextRef& ec) const override;

 private:
  /// Audit netlink subscription handle
  NetlinkSubscriptionHandle audit_netlink_subscription_;
};
}
