/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/mutex.h>

#include <set>

namespace osquery {

struct OpenBSMSubscriptionContext : public SubscriptionContext {
  // The id of the event you want to alert on (23 for execve for example)
  int event_id;
};

struct OpenBSMEventContext : public EventContext {
  // The event_id of the OpenBSM log
  int event_id;
  // The tokens for the event to pass to the subscriber
  std::vector<tokenstr_t> tokens;
  // A smart pointer to the memory returned by OpenBSM
  std::shared_ptr<unsigned char> buffer;
};

using OpenBSMEventContextRef = std::shared_ptr<OpenBSMEventContext>;
using OpenBSMSubscriptionContextRef =
    std::shared_ptr<OpenBSMSubscriptionContext>;

/// This is a dispatched service that handles published audit replies.
class OpenBSMConsumerRunner;

class OpenBSMEventPublisher
    : public EventPublisher<OpenBSMSubscriptionContext, OpenBSMEventContext> {
  DECLARE_PUBLISHER("openbsm");

 public:
  Status setUp() override;

  void configure() override;

  void tearDown() override;

  /// Poll the audit descriptor until the publisher is interrupted.
  Status run() override;

  OpenBSMEventPublisher(const std::string& name = "OpenBSMEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  virtual ~OpenBSMEventPublisher() {
    tearDown();
  }

 private:
  /// Dequeue from the audit descriptor when data is available.
  void acquireMessages();

  Status configureAuditPipe();

  /// Apply normal subscription to event matching logic.
  bool shouldFire(const OpenBSMSubscriptionContextRef& mc,
                  const OpenBSMEventContextRef& ec) const override;

 private:
  FILE* audit_pipe_{nullptr};
  Mutex audit_pipe_mutex_;

  /// Total set of event IDs from subscriptions.
  std::set<size_t> event_ids_;
  Mutex event_ids_mutex_;
};
} // namespace osquery
