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
#include <boost/utility/string_ref.hpp>

#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/audit.h"

namespace osquery {
REGISTER(AuditEventPublisher, "event_publisher", "audit");

// External flags
DECLARE_bool(audit_allow_process_events);
DECLARE_bool(audit_allow_sockets);

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

boost::optional<AuditFields> AuditAssembler::add(const std::string& id,
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

void AuditAssembler::evict(const std::string& id) {
  queue_.erase(std::remove(queue_.begin(), queue_.end(), id), queue_.end());
  mt_.erase(id);
  m_.erase(id);
}

void AuditAssembler::shuffle(const std::string& id) {
  queue_.erase(std::remove(queue_.begin(), queue_.end(), id), queue_.end());
  queue_.push_back(id);
}

bool AuditAssembler::complete(const std::string& id) {
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
  if (!FLAGS_audit_allow_process_events && !FLAGS_audit_allow_sockets) {
    return Status(1, "Subscriber disabled via configuration");
  }

  return Status(0, "OK");
}

void AuditEventPublisher::configure() {
  // Only subscribe if we are actually going to have listeners
  if (audit_netlink_subscription_ == 0) {
    audit_netlink_subscription_ = AuditNetlink::getInstance().subscribe();
  }
}

void AuditEventPublisher::tearDown() {
  if (audit_netlink_subscription_ != 0) {
    AuditNetlink::getInstance().unsubscribe(audit_netlink_subscription_);
    audit_netlink_subscription_ = 0;
  }
}

Status AuditEventPublisher::run() {
  auto audit_event_record_queue =
      AuditNetlink::getInstance().getEvents(audit_netlink_subscription_);

  for (auto& audit_record : audit_event_record_queue) {
    bool handle_reply = false;

    switch (audit_record.type) {
    case NLMSG_NOOP:
    case NLMSG_DONE:
    case NLMSG_ERROR:
    case AUDIT_LIST_RULES:
    case AUDIT_SECCOMP:
    case (AUDIT_GET + 1)...(AUDIT_LIST_RULES - 1):
    case (AUDIT_LIST_RULES + 1)...(AUDIT_FIRST_USER_MSG - 1):
    case AUDIT_DAEMON_START ... AUDIT_DAEMON_CONFIG: // 1200 - 1203
    case AUDIT_CONFIG_CHANGE:
    case AUDIT_EOE: // 1320 (multi-record event).
    case AUDIT_GET:
      break;

    case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
    case AUDIT_SYSCALL: // 1300
    case AUDIT_CWD: // 1307
    case AUDIT_PATH: // 1302
    case AUDIT_EXECVE: // // 1309 (execve arguments).
    default:
      handle_reply = true;
      break;
    }

    // Replies are 'handled' as potential events for several audit types.
    if (!handle_reply) {
      continue;
    }

    auto ec = createEventContext();

    // Build an event context around this reply.
    ec->type = audit_record.type;
    ec->time = audit_record.time;
    ec->audit_id = audit_record.audit_id;

    ec->fields = std::move(audit_record.fields);
    audit_record.fields.clear();

    // There is a special field for syscalls.
    if (ec->fields.count("syscall") == 1) {
      const auto& syscall_string = ec->fields.at("syscall").data();
      long long syscall_number{0};
      if (!safeStrtoll(syscall_string, 10, syscall_number)) {
        syscall_number = 0;
      }

      ec->syscall = static_cast<int>(syscall_number);
    }

    fire(ec);
  }

  return Status(0, "OK");
}

bool AuditEventPublisher::shouldFire(const AuditSubscriptionContextRef& sc,
                                     const AuditEventContextRef& ec) const {
  // User messages allow a catch all configuration.
  if (sc->user_types &&
      (ec->type >= AUDIT_FIRST_USER_MSG && ec->type <= AUDIT_LAST_USER_MSG)) {
    return true;
  }

  for (const auto& audit_event_type : sc->types) {
    // Skip invalid audit event types
    if (audit_event_type == 0)
      continue;

    // Skip audit events that do not match the requested type
    if (audit_event_type != ec->type)
      continue;

    // No further filtering needed for events that are not syscalls
    if (audit_event_type != AUDIT_SYSCALL) {
      return true;
    }

    // We received a syscall event; we have to capture it only if the rule set
    // contains it
    for (const auto& rule : sc->rules) {
      if (rule.syscall == ec->syscall)
        return true;
    }
  }

  return false;
}
}
