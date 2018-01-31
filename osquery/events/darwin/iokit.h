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

#include <atomic>
#include <iomanip>

#include <osquery/events.h>
#include <osquery/status.h>

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>

#include "osquery/core/conversions.h"

namespace osquery {

extern const std::string kIOUSBDeviceClassName_;
extern const std::string kIOPCIDeviceClassName_;
extern const std::string kIOPlatformExpertDeviceClassName_;
extern const std::string kIOACPIPlatformDeviceClassName_;
extern const std::string kIOPlatformDeviceClassname_;

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

struct IOKitPCIProperties {
  std::string vendor_id;
  std::string model_id;
  std::string pci_class;
  std::string driver;

  /// Populate IOKit PCI device properties from the "compatible" property.
  explicit IOKitPCIProperties(const std::string& compatible);
};

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key);
long long int getNumIOKitProperty(const CFMutableDictionaryRef& details,
                                  const std::string& key);

inline void idToHex(std::string& id) {
  long base = 0;
  // = AS_LITERAL(int, id);
  if (safeStrtol(id, 10, base)) {
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0') << (base & 0xFFFF);
    id = hex_id.str();
  }
}

using IOKitEventContextRef = std::shared_ptr<IOKitEventContext>;
using IOKitSubscriptionContextRef = std::shared_ptr<IOKitSubscriptionContext>;

struct DeviceTracker;

class IOKitEventPublisher
    : public EventPublisher<IOKitSubscriptionContext, IOKitEventContext> {
  DECLARE_PUBLISHER("iokit");

 public:
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
