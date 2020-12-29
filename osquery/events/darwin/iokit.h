/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <iomanip>

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>

#include <osquery/events/eventsubscriber.h>
#include <osquery/utils/status/status.h>

namespace osquery {

struct IOKitSubscriptionContext : public SubscriptionContext {
  std::string model_id;
  std::string vendor_id;

  /// Bus type, e.g., USB.
  std::string type;
};

struct IOKitEventContext : public EventContext {
  enum Action {
    DEVICE_ATTACH = 0,
    DEVICE_DETACH,
  };

  Action action;
  std::string type;
  std::string vendor;
  std::string model;
  std::string vendor_id;
  std::string model_id;
  std::string path;
  std::string driver;
  std::string version;
  std::string serial;
};

using IOKitEventContextRef = std::shared_ptr<IOKitEventContext>;
using IOKitSubscriptionContextRef = std::shared_ptr<IOKitSubscriptionContext>;

struct DeviceTracker;

class IOKitEventPublisher
    : public EventPublisher<IOKitSubscriptionContext, IOKitEventContext> {
  DECLARE_PUBLISHER("iokit");

 public:
  IOKitEventPublisher(const std::string& name = "IOKitEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  void tearDown() override;

  Status run() override;

  bool shouldFire(const IOKitSubscriptionContextRef& sc,
                  const IOKitEventContextRef& ec) const override;

 public:
  // Callbacks
  static void deviceAttach(void* refcon, io_iterator_t iterator);
  static void deviceDetach(void* refcon,
                           io_service_t device,
                           natural_t type,
                           void*);

  void newEvent(const io_service_t& device, IOKitEventContext::Action action);

 private:
  void restart();
  void stop() override;

 private:
  /// The publisher state machine will start, restart, and stop the run loop.
  CFRunLoopRef run_loop_{nullptr};

  /// Notification port, should close.
  IONotificationPortRef port_{nullptr};

  /// Device attach iterator.
  io_iterator_t iterator_;

  /// Device detach notification.
  std::vector<std::shared_ptr<struct DeviceTracker>> devices_;

  /// Device notification and container access protection mutex.
  mutable Mutex mutex_;

  /**
   * @brief Should events be emitted by the callback.
   *
   * The callback registration initially returns all matches, these must be
   * consumed by an iterator walk. Do not emit events for this initial seed.
   * The publisher started boolean is set after a successful restart.
   */
  std::atomic<bool> publisher_started_{false};
};
}
