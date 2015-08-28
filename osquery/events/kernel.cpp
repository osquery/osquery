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

FLAG(bool, disable_kernel, false, "Disable osquery kernel extension");

static const size_t shared_buffer_size_bytes = (20 * (1 << 20));
static const int max_events_before_sync = 1000;

REGISTER(KernelEventPublisher, "event_publisher", "kernel");

Status KernelEventPublisher::setUp() {
  if (kToolType == OSQUERY_TOOL_DAEMON) {
    loadKernelExtension();
  }

  try {
    queue_ = new CQueue(shared_buffer_size_bytes);
  } catch (const CQueueException &e) {
    if (kToolType == OSQUERY_TOOL_DAEMON) {
      LOG(INFO) << "Cannot connect to kernel. " << e.what();
    }
    queue_ = nullptr;
    return Status(0, e.what());
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
      queue_->subscribe(sc->event_type, sc->udata);
    }
  }
}

void KernelEventPublisher::tearDown() {
  if (queue_ != nullptr) {
    delete queue_;
  }
}

Status KernelEventPublisher::run() {
  if (queue_ == nullptr) {
    return Status(1, "No kernel communication.");
  }

  // Perform queue read min/max synchronization.
  try {
    int drops = 0;
    if ((drops = queue_->kernelSync(OSQUERY_DEFAULT)) > 0 &&
        kToolType == OSQUERY_TOOL_DAEMON) {
      LOG(WARNING) << "Dropping " << drops << " kernel events";
    }
  } catch (const CQueueException &e) {
    LOG(WARNING) << e.what();
  }

  // Iterate over each event type in the queue and appropriately fire each.
  int max_before_sync = max_events_before_sync;
  KernelEventContextRef ec;
  osquery_event_t event_type = OSQUERY_NULL_EVENT;
  CQueue::event *event = nullptr;
  while (max_before_sync > 0 && (event_type = queue_->dequeue(&event))) {
    // Each event type may use a specific event type structure.
    switch (event_type) {
      case OSQUERY_PROCESS_EVENT:
        ec = createEventContextFrom<osquery_process_event_t>(event_type, event);
        fire(ec);
        break;
      case OSQUERY_FILE_EVENT:
        ec = createEventContextFrom<osquery_file_event_t>(event_type, event);
        fire(ec);
        break;
      default:
        LOG(WARNING) << "Unknown kernel event received: " << event_type;
        break;
    }
    max_before_sync--;
  }

  return Status(0, "Continue");
}

template <typename EventType>
KernelEventContextRef KernelEventPublisher::createEventContextFrom(
    osquery_event_t event_type, CQueue::event *event) const {
  TypedKernelEventContextRef<EventType> ec;

  ec = std::make_shared<TypedKernelEventContext<EventType> >();
  ec->event_type = event_type;
  ec->time = event->time.time;
  ec->uptime = event->time.uptime;
  memcpy(&(ec->event), event->buf, sizeof(EventType));
  ec->flexible_data.insert(ec->flexible_data.begin(),
                           event->buf + sizeof(EventType),
                           event->buf + event->size);

  return std::static_pointer_cast<KernelEventContext>(ec);
}

bool KernelEventPublisher::shouldFire(const KernelSubscriptionContextRef &sc,
                                      const KernelEventContextRef &ec) const {
  return ec->event_type == sc->event_type;
}
}  // namespace osquery
