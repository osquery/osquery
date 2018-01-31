/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <vector>

#include <osquery/events.h>
#include <osquery/status.h>

#include "osquery/events/kernel/circular_queue_user.h"

namespace osquery {

/**
 * @brief Name of the kernel communication device node.
 *
 * The kernel component creates an ioctl API for synchronizing kernel-based
 * subscriptions and userland access to regions of shared memory.
 */
extern const std::string kKernelDevice;

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

  /// Optional category passed to the callback.
  std::string category;
};

/**
 * @brief Event details for a KernelEventPubliser events.
 */
struct KernelEventContext : public EventContext {
  /// The event type.
  osquery_event_t event_type;

  /// The observed uptime of the system at event time.
  uint32_t uptime{0};
};

template <typename EventType>
struct TypedKernelEventContext : public KernelEventContext {
  EventType event;

  // The flexible data must remain as the last member.
  std::vector<char> flexible_data;
};

using KernelSubscriptionContextRef = std::shared_ptr<KernelSubscriptionContext>;
using KernelEventContextRef = std::shared_ptr<KernelEventContext>;

template <typename EventType>
using TypedKernelEventContextRef =
    std::shared_ptr<TypedKernelEventContext<EventType>>;

class KernelEventPublisher
    : public EventPublisher<KernelSubscriptionContext, KernelEventContext> {
  DECLARE_PUBLISHER("kernel");

 public:
  KernelEventPublisher() : EventPublisher(), queue_(nullptr) {}

  /**
   * @brief Attempt to load the platform's kernel component.
   *
   * This method starts the kernel event publisher. As a convenience, the daemon
   * will try to start/add/load the kernel component. For example on OS X this
   * will load the osquery kernel extension if available. Each platform should
   * include a `osquery::loadKernelExtension` method to perform the load.
   *
   * The osquery kernel component expects to make a queue available to the
   * daemon, so the setup method will attempt to connect and request
   * initialization of the queue, see the `osquery::CQueue` APIs.
   *
   * This should return a failure status if the queue cannot be initialized.
   */
  Status setUp() override;

  /**
   * @brief Translate event subscribers into kernel subscriptions.
   *
   * The kernel component also uses a subscription abstraction. We expect to
   * register kernel-based callbacks or start kernel threads that publish into
   * a circular queue. When the queue is initialized it may communicate to each
   * of these kernel publishers.
   */
  void configure() override;

  void stop() override;

  /**
   * @brief Remove the circular queue.
   */
  void tearDown() override { stop(); }

  /**
   * @brief Continue to flush the queue.
   */
  Status run() override;

 private:
  /// Queue access mutex.
  Mutex mutex_;

  CQueue *queue_{nullptr};

  /// Check whether the subscription matches the event.
  bool shouldFire(const KernelSubscriptionContextRef &sc,
                  const KernelEventContextRef &ec) const override;

  template <typename EventType>
  KernelEventContextRef createEventContextFrom(osquery_event_t event_type,
                                               CQueue::event *event) const;
};

} // namespace osquery
