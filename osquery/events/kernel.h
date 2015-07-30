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

#include "osquery/events/kernel/circular_queue_user.h"

#include <osquery/events.h>
#include <osquery/status.h>

#include <vector>

namespace osquery {

/**
 * @brief Load kernel extension if applicable.
 */
void loadKernelExtension();

/**
 * @brief Subscription details for KernelEventPublisher events.
 */
struct KernelSubscriptionContext : public SubscriptionContext {
  /// The kernel event subscription type.
  osquery_event_t event_type;

  /// Data to pass to the kernel.
  void *udata;
};

/**
 * @brief Event details for a KernelEventPubliser events.
 */
struct KernelEventContext : public EventContext {
  /// The event type.
  osquery_event_t event_type;

  uint32_t uptime;
};

template <typename EventType>
struct TypedKernelEventContext : public KernelEventContext {
  EventType event;
  std::vector<char> flexible_data;
};

typedef std::shared_ptr<KernelSubscriptionContext> KernelSubscriptionContextRef;
typedef std::shared_ptr<KernelEventContext> KernelEventContextRef;
template <typename EventType>
using TypedKernelEventContextRef =
  std::shared_ptr<TypedKernelEventContext<EventType> >;

class KernelEventPublisher
    : public EventPublisher<KernelSubscriptionContext, KernelEventContext> {
  DECLARE_PUBLISHER("kernel");

 public:
  KernelEventPublisher() : EventPublisher(), queue_(nullptr) {}

  Status setUp();
  void configure();
  void tearDown();

  Status run();

 private:
  CQueue *queue_;

  /// Check whether the subscription matches the event.
  bool shouldFire(const KernelSubscriptionContextRef &sc,
                  const KernelEventContextRef &ec) const;

  template <typename EventType>
  KernelEventContextRef createEventContextFrom(osquery_event_t event_type,
                                               CQueue::event *event) const;
};

}  // namespace osquery
