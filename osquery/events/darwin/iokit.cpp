/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <IOKit/IOMessage.h>

#include <osquery/core/tables.h>
#include <osquery/events/darwin/iokit.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {

REGISTER(IOKitEventPublisher, "event_publisher", "iokit");

struct DeviceTracker : private boost::noncopyable {
 public:
  explicit DeviceTracker(IOKitEventPublisher* p) : publisher(p) {}

 public:
  IOKitEventPublisher* publisher{nullptr};
  io_object_t notification{0};
};


void IOKitEventPublisher::restart() {
  static std::vector<const std::string*> device_classes = {
      &kIOUSBDeviceClassName_,
      &kIOPCIDeviceClassName_,
      &kIOPlatformExpertDeviceClassName_,
      &kIOACPIPlatformDeviceClassName_,
      &kIOPlatformDeviceClassname_,
  };

  if (run_loop_ == nullptr) {
    return;
  }

  // Remove any existing stream.
  stop();

  {
    WriteLock lock(mutex_);
    port_ = IONotificationPortCreate(kIOMasterPortDefault);
    // Get a run loop source from the created IOKit notification port.
    auto run_loop_source = IONotificationPortGetRunLoopSource(port_);
    CFRunLoopAddSource(run_loop_, run_loop_source, kCFRunLoopDefaultMode);
  }

  publisher_started_ = false;
  for (const auto& class_name : device_classes) {
    // Service matching is USB for now, must find a way to get more!
    // Can provide a "IOPCIDevice" here too.
    auto matches = IOServiceMatching(class_name->c_str());

    // Register attach/detaches (could use kIOPublishNotification).
    // Notification types are defined in IOKitKeys.
    IOReturn result = kIOReturnSuccess + 1;
    {
      WriteLock lock(mutex_);
      if (port_ == nullptr) {
        return;
      }
      result = IOServiceAddMatchingNotification(
          port_,
          kIOFirstMatchNotification,
          matches,
          (IOServiceMatchingCallback)deviceAttach,
          this,
          &iterator_);
    }
    if (result == kIOReturnSuccess) {
      deviceAttach(this, iterator_);
    }
  }
  publisher_started_ = true;
}

void IOKitEventPublisher::newEvent(const io_service_t& device,
                                   IOKitEventContext::Action action) {
  auto ec = createEventContext();
  ec->action = action;

  {
    // The IORegistry name is not needed.
    io_name_t class_name = {0};
    if (IOObjectGetClass(device, class_name) != kIOReturnSuccess) {
      return;
    }
    ec->type = std::string(class_name);
  }

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);
  if (ec->type == kIOUSBDeviceClassName_) {
    ec->path = getIOKitProperty(details, "USB Address") + ":";
    ec->path += getIOKitProperty(details, "PortNum");
    ec->model = getIOKitProperty(details, "USB Product Name");
    ec->model_id = getIOKitProperty(details, "idProduct");
    ec->vendor = getIOKitProperty(details, "USB Vendor Name");
    ec->vendor_id = getIOKitProperty(details, "idVendor");
    idToHex(ec->vendor_id);
    idToHex(ec->model_id);
    ec->serial = getIOKitProperty(details, "USB Serial Number");
    if (ec->serial.size() == 0) {
      ec->serial = getIOKitProperty(details, "iSerialNumber");
    }
    ec->version = "";
    ec->driver = getIOKitProperty(details, "IOUserClientClass");
  } else if (ec->type == kIOPCIDeviceClassName_) {
    auto compatible = getIOKitProperty(details, "compatible");
    auto properties = IOKitPCIProperties(compatible);
    ec->model_id = properties.model_id;
    ec->vendor_id = properties.vendor_id;
    ec->driver = properties.driver;
    if (ec->driver.empty()) {
      ec->driver = getIOKitProperty(details, "IOName");
    }

    ec->path = getIOKitProperty(details, "pcidebug");
    ec->version = getIOKitProperty(details, "revision-id");
    ec->model = getIOKitProperty(details, "model");
  } else {
    // Get the name as the model.
    io_name_t name = {0};
    IORegistryEntryGetName(device, name);
    if (name[0] != 0) {
      ec->model = std::string(name);
    }
  }

  CFRelease(details);
  fire(ec);
}

void IOKitEventPublisher::deviceAttach(void* refcon, io_iterator_t iterator) {
  auto self = (IOKitEventPublisher*)refcon;
  io_service_t device;
  // The iterator may also have become invalid due to a change in the registry.
  // It is possible to reiterate devices, but that will cause duplicate events.
  while ((device = IOIteratorNext(iterator))) {
    {
      WriteLock lock(self->mutex_);
      if (self->port_ == nullptr) {
        IOObjectRelease(device);
        continue;
      }

      // Create a notification tracker.
      auto tracker = std::make_shared<struct DeviceTracker>(self);
      self->devices_.push_back(tracker);
      IOServiceAddInterestNotification(self->port_,
                                       device,
                                       kIOGeneralInterest,
                                       (IOServiceInterestCallback)deviceDetach,
                                       tracker.get(),
                                       &(tracker->notification));
    }
    if (self->publisher_started_) {
      self->newEvent(device, IOKitEventContext::Action::DEVICE_ATTACH);
    }
    IOObjectRelease(device);
  }
}

void IOKitEventPublisher::deviceDetach(void* refcon,
                                       io_service_t device,
                                       natural_t message_type,
                                       void*) {
  if (message_type != kIOMessageServiceIsTerminated) {
    // This is an unexpected notification.
    return;
  }

  auto* tracker = (struct DeviceTracker*)refcon;
  auto* self = tracker->publisher;
  // The device tracker allows us to emit using the publisher and release the
  // notification created for this device.
  self->newEvent(device, IOKitEventContext::Action::DEVICE_DETACH);
  IOObjectRelease(device);

  {
    WriteLock lock(self->mutex_);
    // Remove the device tracker.
    IOObjectRelease(tracker->notification);
    auto it = self->devices_.begin();
    while (it != self->devices_.end()) {
      if ((*it)->notification == tracker->notification) {
        IOObjectRelease((*it)->notification);
        self->devices_.erase(it);
        break;
      }
      it++;
    }
  }
}

Status IOKitEventPublisher::run() {
  // The run entrypoint executes in a dedicated thread.
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    // Restart the stream creation.
    restart();
  }

  // Start the run loop, it may be removed with a tearDown.
  CFRunLoopRun();
  return Status::success();
}

bool IOKitEventPublisher::shouldFire(const IOKitSubscriptionContextRef& sc,
                                     const IOKitEventContextRef& ec) const {
  if (!sc->type.empty() && sc->type != ec->type) {
    return false;
  } else if (!sc->model_id.empty() && sc->model_id != ec->model_id) {
    return false;
  } else if (!sc->vendor_id.empty() && sc->vendor_id != ec->vendor_id) {
    return false;
  }

  return true;
}

void IOKitEventPublisher::stop() {
  if (run_loop_ == nullptr) {
    // If there is no run loop then the publisher thread has not started.
    return;
  }

  // Stop the run loop.
  WriteLock lock(mutex_);
  CFRunLoopStop(run_loop_);

  // Stop the run loop before operating on containers.
  // Destroy the IOPort.
  if (port_ != nullptr) {
    auto source = IONotificationPortGetRunLoopSource(port_);
    if (CFRunLoopContainsSource(run_loop_, source, kCFRunLoopDefaultMode)) {
      CFRunLoopRemoveSource(run_loop_, source, kCFRunLoopDefaultMode);
    }
    // And destroy the port.
    IONotificationPortDestroy(port_);
    port_ = nullptr;
  }

  // Clear all devices and their notifications.
  for (const auto& device : devices_) {
    IOObjectRelease(device->notification);
  }
  devices_.clear();
}

void IOKitEventPublisher::tearDown() {
  stop();

  // Do not keep a reference to the run loop.
  run_loop_ = nullptr;
}
}
