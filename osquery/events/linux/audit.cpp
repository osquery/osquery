/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <poll.h>

#include <queue>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem.hpp>
#include <boost/utility/string_ref.hpp>

#include <osquery/dispatcher.h>
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

HIDDEN_FLAG(uint64, audit_queue_size, 8192 * 4, "Size of the userland queue");

HIDDEN_FLAG(bool, audit_debug, false, "Debug Linux audit messages");

REGISTER(AuditEventPublisher, "event_publisher", "audit");

enum AuditStatus {
  AUDIT_DISABLED = 0,
  AUDIT_ENABLED = 1,
  AUDIT_IMMUTABLE = 2,
};

class AuditConsumer : private boost::noncopyable {
 public:
  static AuditConsumer& get() {
    static AuditConsumer instance;
    return instance;
  }

  /// Add and copy an audit reply into the queue.
  void push(AuditEventContextRef& reply);

  /// Inspect the front of the queue, usually to move the content.
  AuditEventContextRef& peek();

  size_t size() const;

  /// Remove the front element.
  void pop();

 private:
  /// The managed thread-unsafe queue.
  std::queue<AuditEventContextRef> queue_;

  /// An observed max-size of the queue.
  size_t max_size_;

  /// The queue-protecting Mutex.
  mutable Mutex mutex_;
};

class AuditConsumerRunner : public InternalRunnable {
 public:
  AuditConsumerRunner(AuditEventPublisher* publisher) : publisher_(publisher) {}

  /// Thread entrypoint.
  void start() override;

 private:
  AuditEventPublisher* publisher_;
};

void AuditAssembler::start(size_t capacity,
                           std::vector<size_t> types,
                           AuditUpdate update) {
  capacity_ = capacity;
  update_ = update;

  queue_.clear();
  queue_.reserve(capacity_);
  mt_.clear();
  m_.clear();

  types_ = std::move(types);
}

boost::optional<AuditFields> AuditAssembler::add(AuditId id,
                                                 size_t type,
                                                 const AuditFields& fields) {
  auto it = m_.find(id);
  if (it == m_.end()) {
    // A new audit ID.
    if (queue_.size() == capacity_) {
      evict(queue_.front());
    }

    if (types_.size() == 1 && type == types_[0]) {
      // This is an easy match.
      AuditFields r;
      if (update_ == nullptr) {
        m_[id] = {};
        return boost::none;
      } else if (!update_(type, fields, r)) {
        return boost::none;
      }
      return r;
    }

    // Add the type, push the ID onto the queue, and update.
    mt_[id] = {type};
    queue_.push_back(id);
    if (update_ == nullptr) {
      m_[id] = {};
    } else {
      update_(type, fields, m_[id]);
    }
    return boost::none;
  }

  // Add the type and update.
  auto& mt = mt_[id];
  if (std::find(mt.begin(), mt.end(), type) == mt.end()) {
    mt.push_back(type);
  }

  if (update_ != nullptr && !update_(type, fields, m_[id])) {
    evict(id);
    return boost::none;
  }

  // Check if the message is complete (all types seen).
  if (complete(id)) {
    auto new_fields = std::move(it->second);
    evict(id);
    return new_fields;
  }

  // Move the audit ID to the front of the queue.
  shuffle(id);
  return boost::none;
}

void AuditAssembler::evict(AuditId id) {
  queue_.erase(std::remove(queue_.begin(), queue_.end(), id), queue_.end());
  mt_.erase(id);
  m_.erase(id);
}

void AuditAssembler::shuffle(AuditId id) {
  queue_.erase(std::remove(queue_.begin(), queue_.end(), id), queue_.end());
  queue_.push_back(id);
}

bool AuditAssembler::complete(AuditId id) {
  // Is this type enough.
  const auto& types = mt_.at(id);
  for (const auto& t : types_) {
    if (std::find(types.begin(), types.end(), t) == types.end()) {
      return false;
    }
  }
  return true;
}

Status AuditEventPublisher::setUp() {
  if (FLAGS_disable_audit) {
    return Status(1, "Publisher disabled via configuration");
  }

  handle_ = audit_open();
  if (handle_ <= 0) {
    // Could not open the audit subsystem.
    return Status(1, "Could not open audit subsystem");
  }

  // The setup can try to enable auditing.
  if (FLAGS_audit_allow_config) {
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
  if (!immutable_) {
    if (audit_set_pid(handle_, getpid(), WAIT_YES) < 0) {
      // Could not set our process as the userspace auditing daemon.
      return Status(1, "Could not set audit PID");
    }
    // This process is now in control of audit.
    control_ = true;

    // Want to set a min sane buffer and maximum number of events/second min.
    // This is normally controlled through the audit config, but we must
    // enforce sane minimums: -b 8192 -e 100
    audit_set_backlog_wait_time(handle_, 1);
    audit_set_backlog_limit(handle_, 1024);
    audit_set_failure(handle_, AUDIT_FAIL_SILENT);

    // Request only the highest priority of audit status messages.
    set_aumessage_mode(MSG_QUIET, DBG_NO);
  }

  Dispatcher::addService(std::make_shared<AuditConsumerRunner>(this));
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
    if (!FLAGS_disable_audit && subscriptions_.size() > 0) {
      // Audit is enabled, with subscriptions, but they cannot be added.
      VLOG(1)
          << "Linux audit cannot be configured: no privileges or mutability";
    }
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
      VLOG(1) << "Adding audit rule: syscall=" << scr.syscall
              << " action=" << scr.action << " filter='" << scr.filter << "'";
      int rc = audit_add_rule_data(handle_, &rule.rule, scr.flags, scr.action);
      if (rc < 0) {
        // Problem adding rule. If errno == EEXIST then fine.
        LOG(WARNING) << "Cannot add audit rule: syscall=" << scr.syscall
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

    // Restore audit configuration defaults.
    audit_set_backlog_limit(handle_, 0);
    audit_set_backlog_wait_time(handle_, 60000);
    audit_set_failure(handle_, AUDIT_FAIL_PRINTK);
    audit_set_enabled(handle_, AUDIT_DISABLED);
  }

  audit_close(handle_);
  handle_ = 0;
}

inline void handleAuditConfigChange(const struct audit_reply& reply) {
  // Another daemon may have taken control.
}

inline bool checkUserCache(AuditId aid) {
  static std::vector<AuditId> kAuditUserEventCache;

  // User events may be repeated, store the last 10 audit IDs.
  // Drop duplicates for those last 10.
  if (std::find(kAuditUserEventCache.begin(),
                kAuditUserEventCache.end(),
                aid) != kAuditUserEventCache.end()) {
    return false;
  } else {
    if (kAuditUserEventCache.size() > 10) {
      kAuditUserEventCache.erase(kAuditUserEventCache.begin());
    }
    kAuditUserEventCache.push_back(aid);
  }
  return true;
}

bool handleAuditReply(const struct audit_reply& reply,
                      AuditEventContextRef& ec) {
  // Build an event context around this reply.
  ec->type = reply.type;
  // Tokenize the message.
  boost::string_ref message_view(reply.message, reply.len);
  auto preamble_end = message_view.find("): ");
  if (preamble_end == std::string::npos) {
    return false;
  }

  safeStrtoul(std::string(message_view.substr(6, 10)), 10, ec->time);
  safeStrtoul(std::string(message_view.substr(21, preamble_end - 21)),
              10,
              ec->audit_id);
  boost::string_ref field_view(message_view.substr(preamble_end + 3));

  // The linear search will construct series of key value pairs.
  std::string key, value;
  key.reserve(20);
  value.reserve(256);

  // There are several ways of representing value data (enclosed strings, etc).
  bool found_assignment{false}, found_enclose{false};
  for (const auto& c : field_view) {
    // Iterate over each character in the audit message.
    if ((found_enclose && c == '"') || (!found_enclose && c == ' ')) {
      if (c == '"') {
        value += c;
      }
      // This is a terminating sequence, the end of an enclosure or space tok.
      if (!key.empty()) {
        // Multiple space tokens are supported.
        ec->fields.emplace(std::make_pair(std::move(key), std::move(value)));
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
    ec->fields.emplace(std::make_pair(std::move(key), std::move(value)));
  }

  if (FLAGS_audit_debug) {
    fprintf(stdout, "%zu: (%d) ", ec->audit_id, ec->type);
    for (const auto& f : ec->fields) {
      fprintf(stdout, "%s=%s ", f.first.c_str(), f.second.c_str());
    }
    fprintf(stdout, "\n");
  }

  if (ec->type >= AUDIT_FIRST_USER_MSG && ec->type <= AUDIT_LAST_USER_MSG) {
    if (!checkUserCache(ec->audit_id)) {
      return false;
    }
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

static inline bool adjust_reply(struct audit_reply* rep, int len) {
  rep->type = rep->msg.nlh.nlmsg_type;
  rep->len = rep->msg.nlh.nlmsg_len;
  rep->nlh = &rep->msg.nlh;
  rep->status = nullptr;
  rep->ruledata = nullptr;
  rep->login = nullptr;
  rep->message = nullptr;
  rep->error = nullptr;
  rep->signal_info = nullptr;
  rep->conf = nullptr;
  if (!NLMSG_OK(rep->nlh, static_cast<unsigned int>(len))) {
    if (len == sizeof(rep->msg)) {
      errno = EFBIG;
    } else {
      errno = EBADE;
    }
    return false;
  }

  switch (rep->type) {
  case AUDIT_GET:
    rep->status = static_cast<struct audit_status*>(NLMSG_DATA(rep->nlh));
    break;
  case AUDIT_LIST_RULES:
    rep->ruledata = static_cast<struct audit_rule_data*>(NLMSG_DATA(rep->nlh));
    break;
  case AUDIT_USER:
  case AUDIT_LOGIN:
  case AUDIT_KERNEL:
  case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
  case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
  case AUDIT_FIRST_EVENT ... AUDIT_INTEGRITY_LAST_MSG:
    rep->message = static_cast<char*>(NLMSG_DATA(rep->nlh));
  default:
    break;
  }
  return true;
}

static inline int safe_audit_get_reply(int fd, struct audit_reply* rep) {
  if (fd < 0) {
    return -EBADF;
  }

  struct pollfd fds[1];
  fds[0].fd = fd;
  fds[0].events = POLLIN;

  if (::poll(fds, 1, 4) <= 0) {
    return (errno == EINTR || errno == EAGAIN) ? 0 : -errno;
  }

  if (!(fds[0].revents & POLLIN)) {
    // No input data.
    return -1;
  }

  struct sockaddr_nl nladdr;
  socklen_t nladdrlen = sizeof(nladdr);

  int len = recvfrom(fd,
                     &rep->msg,
                     sizeof(rep->msg),
                     0,
                     (struct sockaddr*)&nladdr,
                     &nladdrlen);
  if (len < 0) {
    return -errno;
  }

  if (nladdrlen != sizeof(nladdr)) {
    return -EPROTO;
  }

  if (nladdr.nl_pid) {
    return -EINVAL;
  }

  if (!adjust_reply(rep, len)) {
    return -errno;
  }
  return len;
}

void AuditConsumer::push(AuditEventContextRef& reply) {
  auto& self = get();
  WriteLock lock(self.mutex_);

  if (self.queue_.size() > FLAGS_audit_queue_size) {
    // The userland queue is filled, drop.
    return;
  }
  self.queue_.push(reply);
}

AuditEventContextRef& AuditConsumer::peek() {
  ReadLock lock(get().mutex_);

  return get().queue_.front();
}

void AuditConsumer::pop() {
  auto& self = get();
  WriteLock lock(self.mutex_);

  self.queue_.pop();

  if (self.queue_.size() > self.max_size_) {
    self.max_size_ = self.queue_.size();
  } else if (self.queue_.empty() && self.max_size_ > 100) {
    std::queue<AuditEventContextRef> empty;
    std::swap(empty, self.queue_);
    self.max_size_ = 0;
  }
}

size_t AuditConsumer::size() const {
  ReadLock lock(get().mutex_);

  return get().queue_.size();
}

void AuditConsumerRunner::start() {
  while (!interrupted()) {
    size_t events = AuditConsumer::get().size();
    for (size_t i = 0; i < events; i++) {
      // Build the event context from the reply type and parse the message.
      publisher_->fire(AuditConsumer::get().peek());
      AuditConsumer::get().pop();
    }

    if (!interrupted() && events == 0) {
      // Only pause if there were no events to process.
      pauseMilli(1000);
    }
  }
}

Status AuditEventPublisher::run() {
  if (!FLAGS_disable_audit && (count_ == 0 || count_++ % 10 == 0)) {
    // Request an update to the audit status.
    // This will also fill in the status on first run.
    audit_request_status(handle_);
  }

  auto inspectReply = ([this]() {
    bool handle_reply = false;

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
    case AUDIT_SECCOMP:
      break;
    case AUDIT_GET:
      // Make a copy of the status reply and store as the most-recent.
      if (reply_.status != nullptr) {
        memcpy(&status_, reply_.status, sizeof(struct audit_status));
      }
      break;
    case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
      handle_reply = true;
      break;
    case (AUDIT_GET + 1)...(AUDIT_LIST_RULES - 1):
    case (AUDIT_LIST_RULES + 1)...(AUDIT_FIRST_USER_MSG - 1):
      // Not interested in handling meta-commands and actions.
      break;
    case AUDIT_DAEMON_START ... AUDIT_DAEMON_CONFIG: // 1200 - 1203
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
    case AUDIT_FIRST_SELINUX ... AUDIT_LAST_SELINUX:
      break;
    case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
      break;
    default:
      // All other cases, pass to reply.
      handle_reply = false;
    }

    // Replies are 'handled' as potential events for several audit types.
    if (handle_reply) {
      auto ec = createEventContext();
      if (handleAuditReply(reply_, ec)) {
        AuditConsumer::get().push(ec);
      }
    }
  });

  // Reset the reply data.
  int result = 0;
  do {
    // Request a reply in a non-blocking mode.
    // This allows the publisher's run loop to periodically request an audit
    // status update. These updates can check for other processes attempting to
    // gain control over the audit sink.
    // This non-blocking also allows faster receipt of multi-message events.
    result = safe_audit_get_reply(handle_, &reply_);

    if (result > 0) {
      inspectReply();
    }
  } while (result > 0 && !isEnding());

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
