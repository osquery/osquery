/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/events/kernel.h"

namespace osquery {

FLAG(bool, disable_kernel, false, "Disable osquery kernel extension");

const std::string kKernelDevice = "/dev/osquery";

/// Kernel shared buffer size in bytes.
static const size_t kKernelQueueSize = (20 * (1 << 20));

/// Handle a maximum of 1000 events before requesting a resync.
static const int kKernelEventsSyncMax = 1000;

/// Handle a maximum of 10 events before request another lock.
static const int kKernelEventsIterate = 10;

REGISTER(KernelEventPublisher, "event_publisher", "kernel");

Status KernelEventPublisher::setUp() {
  // A daemon should attempt to autoload kernel extensions.
  if (kToolType == ToolType::DAEMON) {
    loadKernelExtension();
  }

  // Regardless of the status of the kernel extension, if the device node does
  // not exist then the kernel publisher will silently shutdown.
  // This is not considered an error, and does not emit an error log.
  if (!isWritable(kKernelDevice)) {
    return Status(2, "Cannot access " + kKernelDevice);
  }

  // Assume the kernel extension is loaded, initialize the queue.
  // This will open the extension descriptor and synchronize queue data.
  // If any other daemons or osquery processes are using the queue this fails.
  try {
    WriteLock lock(mutex_);
    queue_ = new CQueue(kKernelDevice, kKernelQueueSize);
  } catch (const CQueueException &e) {
    queue_ = nullptr;
    return Status(1, e.what());
  }

  if (queue_ == nullptr) {
    return Status(1, "Could not allocate CQueue object");
  }

  return Status(0, "OK");
}

void KernelEventPublisher::configure() {
  WriteLock lock(mutex_);
  for (const auto &sub : subscriptions_) {
    if (queue_ != nullptr) {
      auto sc = getSubscriptionContext(sub->context);
      queue_->subscribe(sc->event_type);
    }
  }
}

void KernelEventPublisher::stop() {
  WriteLock lock(mutex_);
  if (queue_ != nullptr) {
    delete queue_;
    queue_ = nullptr;
  }
}

Status KernelEventPublisher::run() {
  {
    WriteLock lock(mutex_);
    if (queue_ == nullptr) {
      return Status(1, "No kernel communication");
    }
  }

  // Perform queue read min/max synchronization.
  try {
    int drops = 0;
    WriteLock lock(mutex_);
    if ((drops = queue_->kernelSync(OSQUERY_OPTIONS_NO_BLOCK)) > 0 &&
        kToolType == ToolType::DAEMON) {
      LOG(WARNING) << "Dropping " << drops << " kernel events";
    }
  } catch (const CQueueException &e) {
    LOG(WARNING) << "Queue synchronization error: " << e.what();
  }

  auto dequeueEvents = [this]() {
    // Dequeue several events while holding the lock.
    int max_before_lock = kKernelEventsIterate;
    while (max_before_lock > 0) {
      // Request an event from the synchronized, safe, portion of the queue.
      CQueue::event *event = nullptr;
      auto event_type = queue_->dequeue(&event);
      if (event_type == OSQUERY_NULL_EVENT) {
        return false;
      }

      // Each event type may use a specific event type structure.
      KernelEventContextRef ec = nullptr;
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
      max_before_lock--;
    }
    return true;
  };

  // Iterate over each event type in the queue and appropriately fire each.
  int max_before_sync = kKernelEventsSyncMax;
  while (max_before_sync > 0) {
    WriteLock lock(mutex_);
    // The kernel publisher may have been torn down.
    if (queue_ == nullptr) {
      break;
    }
    // A NULL event occurred, stop dequeuing.
    if (!dequeueEvents()) {
      break;
    }
    // Append the number of dequeue events to the synchronization counter.
    max_before_sync -= kKernelEventsIterate;
  }

  // Pause for a cool-off since we implement comms in a no-blocking mode.
  pauseMilli(1000);
  return Status(0, "Continue");
}

template <typename EventType>
KernelEventContextRef KernelEventPublisher::createEventContextFrom(
    osquery_event_t event_type, CQueue::event *event) const {
  TypedKernelEventContextRef<EventType> ec = nullptr;

  ec = std::make_shared<TypedKernelEventContext<EventType>>();
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
} // namespace osquery
