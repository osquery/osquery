/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/kernel.h"

#include <osquery/logger.h>

namespace osquery {

static const size_t shared_buffer_size_bytes = (8 * (1 << 20));
static const int max_events_before_sync = 1000;

REGISTER(KernelEventPublisher, "event_publisher", "kernel");

Status KernelEventPublisher::setUp() {
  try {
    queue_ = new CQueue(shared_buffer_size_bytes);
  } catch (const CQueueException &e) {
    LOG(WARNING) << "Cannot connect to kernel. " << e.what();
    return Status(1, e.what());
  }
  if (queue_ == nullptr) {
    return Status(1, "Could not allocate CQueue object.");
  }

  return Status(0, "OK");
}

void KernelEventPublisher::configure() {
  for (const auto &sub : subscriptions_) {
    if (queue_ != nullptr) {
      auto sc = getSubscriptionContext(sub->context);
      LOG(INFO) << "Subscribing to" << sc->event_type;
      queue_->subscribe(sc->event_type);
    }
  }
}

void KernelEventPublisher::tearDown() {
  if (queue_ != nullptr) {
    delete queue_;
  }
}

Status KernelEventPublisher::run() {
  try {
    queue_->kernelSync(OSQUERY_DEFAULT);
  } catch (const CQueueException &e) {
    LOG(WARNING) << e.what();
  }

  int max_before_sync = max_events_before_sync;
  KernelEventContextRef ec;
  osquery_event_t event = OSQUERY_NULL_EVENT;
  void *event_buf = nullptr;
  while (max_before_sync > 0 && (event = queue_->dequeue(&event_buf))) {
    switch (event) {
      default:
        LOG(WARNING) << "Unknown kernel event received: " << event;
        break;
    }
    max_before_sync--;
  }
  
  return Status(0, "Continue");
}

template <typename EventType>
KernelEventContextRef KernelEventPublisher::createEventContextFrom(
    osquery_event_t event_type,
    void *event_buf) const {
  TypedKernelEventContextRef<EventType> ec;

  ec = std::make_shared<TypedKernelEventContext<EventType> >();
  ec->event_type = event_type;
  memcpy(&(ec->event), event_buf, sizeof(EventType));

  return ec;
}

bool KernelEventPublisher::shouldFire(const KernelSubscriptionContextRef &sc,
                                      const KernelEventContextRef &ec) const {
  return ec->event_type == sc->event_type;
}

}  // namespace osquery
