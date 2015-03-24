/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/events/darwin/iokit_hid.h"

namespace osquery {

size_t IOKitHIDEventPublisher::initial_device_count_ = 0;
size_t IOKitHIDEventPublisher::initial_device_evented_count_ = 0;
boost::mutex IOKitHIDEventPublisher::iokit_match_lock_;

REGISTER(IOKitHIDEventPublisher, "event_publisher", "iokit");

std::string IOKitHIDEventPublisher::getProperty(const IOHIDDeviceRef &device,
                                                const CFStringRef &property) {
  CFTypeRef value = IOHIDDeviceGetProperty(device, property);
  if (value == NULL) {
    return "";
  }

  // Only support CFNumber and CFString types.
  if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    return stringFromCFNumber((CFDataRef)value);
  } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
    return stringFromCFString((CFStringRef)value);
  }
  return "";
}

void IOKitHIDEventPublisher::restart() {
  if (run_loop_ == nullptr) {
    // There is no run loop to restart.
    return;
  }

  // Remove any existing stream.
  stop();

  if (manager_ == nullptr) {
    manager_ = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
  }

  // Match anything.
  IOHIDManagerSetDeviceMatching(manager_, NULL);

  auto status = IOHIDManagerOpen(manager_, kIOHIDOptionsTypeNone);
  if (status != kIOReturnSuccess) {
    LOG(WARNING) << RLOG(617) << "Cannot open IOKit HID Manager";
    return;
  }

  // Enumerate initial set of devices matched before time=0.
  CFSetRef devices = IOHIDManagerCopyDevices(manager_);
  if (devices == nullptr) {
    return;
  }

  initial_device_count_ = CFSetGetCount(devices);
  CFRelease(devices);

  // Register callbacks.
  IOHIDManagerRegisterDeviceMatchingCallback(
      manager_, IOKitHIDEventPublisher::MatchingCallback, NULL);
  IOHIDManagerRegisterDeviceRemovalCallback(
      manager_, IOKitHIDEventPublisher::RemovalCallback, NULL);

  IOHIDManagerScheduleWithRunLoop(manager_, run_loop_, kCFRunLoopDefaultMode);
  manager_started_ = true;
}

void IOKitHIDEventPublisher::MatchingCallback(void *context,
                                              IOReturn result,
                                              void *sender,
                                              IOHIDDeviceRef device) {
  {
    // Must not event on initial list of matches.
    boost::lock_guard<boost::mutex> lock(iokit_match_lock_);
    if (initial_device_count_ > initial_device_evented_count_) {
      initial_device_evented_count_++;
      return;
    }
  }

  fire(device, "add");
}

void IOKitHIDEventPublisher::fire(const IOHIDDeviceRef &device,
                                  const std::string &action) {
  auto ec = createEventContext();
  ec->device = device;
  ec->action = action;

  // Fill in more-useful fields.
  ec->vendor_id = getProperty(device, CFSTR(kIOHIDVendorIDKey));
  ec->model_id = getProperty(device, CFSTR(kIOHIDProductIDKey));
  ec->vendor = getProperty(device, CFSTR(kIOHIDManufacturerKey));
  ec->model = getProperty(device, CFSTR(kIOHIDProductKey));
  ec->transport = getProperty(device, CFSTR(kIOHIDTransportKey));
  ec->primary_usage = getProperty(device, CFSTR(kIOHIDPrimaryUsageKey));
  ec->device_usage = getProperty(device, CFSTR(kIOHIDDeviceUsageKey));

  // Fill in more esoteric properties.
  ec->version = getProperty(device, CFSTR(kIOHIDVersionNumberKey));
  ec->location = getProperty(device, CFSTR(kIOHIDLocationIDKey));
  ec->serial = getProperty(device, CFSTR(kIOHIDSerialNumberKey));
  ec->country_code = getProperty(device, CFSTR(kIOHIDCountryCodeKey));

  EventFactory::fire<IOKitHIDEventPublisher>(ec);
}

void IOKitHIDEventPublisher::RemovalCallback(void *context,
                                             IOReturn result,
                                             void *sender,
                                             IOHIDDeviceRef device) {
  fire(device, "remove");
}

void IOKitHIDEventPublisher::InputValueCallback(void *context,
                                                IOReturn result,
                                                void *sender,
                                                IOHIDValueRef value) {
  // Nothing yet (do not allow value change subscriptions).
  // Value changes contain potentially sensitive data.
}

bool IOKitHIDEventPublisher::shouldFire(
    const IOKitHIDSubscriptionContextRef &sc,
    const IOKitHIDEventContextRef &ec) const {
  if (sc->values) {
    // See InputValueCallback
    return false;
  }

  if (sc->transport != "" && sc->transport != ec->transport) {
    return false;
  } else if (sc->model_id != "" && sc->model_id != ec->model_id) {
    return false;
  } else if (sc->vendor_id != "" && sc->vendor_id != ec->vendor_id) {
    return false;
  } else if (sc->primary_usage != "" &&
             sc->primary_usage != ec->primary_usage) {
    return false;
  } else if (sc->device_usage != "" && sc->device_usage != ec->device_usage) {
    return false;
  }

  return true;
}

Status IOKitHIDEventPublisher::run() {
  // The run entrypoint executes in a dedicated thread.
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    // Restart the stream creation.
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();

  // Add artificial latency to run loop.
  osquery::publisherSleep(1000);
  return Status(0, "OK");
}

void IOKitHIDEventPublisher::stop() {
  // Stop the manager.
  if (manager_ != nullptr) {
    IOHIDManagerUnscheduleFromRunLoop(
        manager_, run_loop_, kCFRunLoopDefaultMode);
    IOHIDManagerClose(manager_, kIOHIDOptionsTypeNone);
    manager_started_ = false;
    manager_ = nullptr;
  }

  // Stop the run loop.
  if (run_loop_ != nullptr) {
    CFRunLoopStop(run_loop_);
  }
}

void IOKitHIDEventPublisher::tearDown() {
  stop();

  // Do not keep a reference to the run loop.
  run_loop_ = nullptr;
}
}
