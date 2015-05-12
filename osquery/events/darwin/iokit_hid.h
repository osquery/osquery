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

#include <CoreServices/CoreServices.h>
#include <IOKit/hid/IOHIDLib.h>

#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

struct IOKitHIDSubscriptionContext : public SubscriptionContext {
  /// Bus type, e.g., USB.
  std::string transport;
  /// Product name
  std::string model_id;
  std::string vendor_id;

  /// Usage types.
  std::string primary_usage;
  std::string device_usage;

  /// Get values from HID events.
  bool values;

  /// Do not request values by default.
  IOKitHIDSubscriptionContext() : values(false) {}
};

struct IOKitHIDEventContext : public EventContext {
  /// The native IOKit device reference.
  IOHIDDeviceRef device;

  /// The event action: add, remove, value change.
  std::string action;
  /// If a value was changed, include the result (optional).
  std::string result;

  /// The publisher pre-populates several fields.
  std::string vendor_id;
  std::string model_id;
  std::string vendor;
  std::string model;
  std::string transport;
  std::string primary_usage;
  std::string device_usage;

  /// More esoteric properties.
  std::string version;
  std::string location;
  std::string serial;
  std::string country_code;
};

typedef std::shared_ptr<IOKitHIDEventContext> IOKitHIDEventContextRef;
typedef std::shared_ptr<IOKitHIDSubscriptionContext>
    IOKitHIDSubscriptionContextRef;

/**
 * @brief An osquery EventPublisher for the Apple IOKit HID notification API.
 *
 */
class IOKitHIDEventPublisher
    : public EventPublisher<IOKitHIDSubscriptionContext, IOKitHIDEventContext> {
  DECLARE_PUBLISHER("iokit_hid");

 public:
  void configure() {}
  void tearDown();

  // Entrypoint to the run loop
  Status run();

 public:
  /// IOKit HID hotplugged event.
  static void MatchingCallback(void *context,
                               IOReturn result,
                               void *sender,
                               IOHIDDeviceRef device);

  /// IOKit HID device removed.
  static void RemovalCallback(void *context,
                              IOReturn result,
                              void *sender,
                              IOHIDDeviceRef device);

  /// IOKit HID device value changed.
  static void InputValueCallback(void *context,
                                 IOReturn result,
                                 void *sender,
                                 IOHIDValueRef value);

 private:
  /// Helper fire fuction to parse properties/actions.
  static void fire(const IOHIDDeviceRef &device, const std::string &action);

 public:
  IOKitHIDEventPublisher() : EventPublisher() {
    manager_started_ = false;
    manager_ = nullptr;
    run_loop_ = nullptr;
  }

  bool shouldFire(const IOKitHIDSubscriptionContextRef &mc,
                  const IOKitHIDEventContextRef &ec) const;

 public:
  /**
   * @brief Get a string representation from an IOKitHID device property.
   *
   * @param device The IOKitHID device from a callback or matching query.
   * @param property The device property key from <IOKit/hid/IOHIDKeys.h>.
   *
   * @return A string representation of the string/number, blank if missing.
   */
  static std::string getProperty(const IOHIDDeviceRef &device,
                                 const CFStringRef &property);

 private:
  /// Restart the run loop.
  void restart();
  /// Stop the manager and the run loop.
  void stop();

 private:
  IOHIDManagerRef manager_;
  bool manager_started_;

 private:
  CFRunLoopRef run_loop_;

 private:
  static size_t initial_device_count_;
  static size_t initial_device_evented_count_;
  static boost::mutex iokit_match_lock_;
};
}
