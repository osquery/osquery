// Copyright 2004-present Facebook. All Rights Reserved.

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/events/linux/udev.h"

namespace osquery {

REGISTER_EVENTPUBLISHER(UdevEventPublisher);

int kUdevULatency = 200;

Status UdevEventPublisher::setUp() {
  // Create the udev object.
  handle_ = udev_new();
  if (!handle_) {
    return Status(1, "Could not create udev object.");
  }

  // Set up the udev monitor before scanning/polling.
  monitor_ = udev_monitor_new_from_netlink(handle_, "udev");
  udev_monitor_enable_receiving(monitor_);

  return Status(0, "OK");
}

void UdevEventPublisher::configure() {}

void UdevEventPublisher::tearDown() {
  if (handle_ != nullptr) {
    udev_unref(handle_);
  }
}

Status UdevEventPublisher::run() {
  int fd = udev_monitor_get_fd(monitor_);
  fd_set set;

  FD_ZERO(&set);
  FD_SET(fd, &set);

  struct timeval timeout = {1, 1000};
  int selector = ::select(fd + 1, &set, nullptr, nullptr, &timeout);
  if (selector == -1) {
    LOG(ERROR) << "Could not read udev monitor";
    return Status(1, "udev monitor failed.");
  }

  if (selector == 0 || !FD_ISSET(fd, &set)) {
    // Read timeout.
    return Status(0, "Timeout");
  }

  struct udev_device *device = udev_monitor_receive_device(monitor_);
  if (device == nullptr) {
    LOG(ERROR) << "udev monitor returned invalid device.";
    return Status(1, "udev monitor failed.");
  }

  auto ec = createEventContext(device);
  fire(ec);

  udev_device_unref(device);

  ::usleep(kUdevULatency);
  return Status(0, "Continue");
}

std::string UdevEventPublisher::getValue(struct udev_device* device,
                                         const std::string& property) {
  auto value = udev_device_get_property_value(device, property.c_str());
  if (value != nullptr) {
    return std::string(value);
  }
  return "";
}

std::string UdevEventPublisher::getAttr(struct udev_device* device,
                                        const std::string& attr) {
  auto value = udev_device_get_sysattr_value(device, attr.c_str());
  if (value != nullptr) {
    return std::string(value);
  }
  return "";
}

UdevEventContextRef UdevEventPublisher::createEventContext(
    struct udev_device* device) {
  auto ec = createEventContext();
  ec->device = device;
  // Map the action string to the eventing enum.
  ec->action = UDEV_EVENT_ACTION_UNKNOWN;
  ec->action_string = std::string(udev_device_get_action(device));
  if (ec->action_string == "add") {
    ec->action = UDEV_EVENT_ACTION_ADD;
  } else if (ec->action_string == "remove") {
    ec->action = UDEV_EVENT_ACTION_REMOVE;
  } else if (ec->action_string == "change") {
    ec->action = UDEV_EVENT_ACTION_CHANGE;
  }

  // Set the subscription-aware variables for the event.
  auto value = udev_device_get_subsystem(device);
  if (value != nullptr) {
    ec->subsystem = std::string(value);
  }

  value = udev_device_get_devnode(device);
  if (value != nullptr) {
    ec->devnode = std::string(value);
  }

  value = udev_device_get_devtype(device);
  if (value != nullptr) {
    ec->devtype = std::string(value);
  }

  value = udev_device_get_driver(device);
  if (value != nullptr) {
    ec->driver = std::string(value);
  }

  return ec;
}

bool UdevEventPublisher::shouldFire(const UdevSubscriptionContextRef& sc,
                                    const UdevEventContextRef& ec) {
  if (sc->action != UDEV_EVENT_ACTION_ALL) {
    if (sc->action != ec->action) {
      return false;
    }
  }

  if (sc->subsystem.length() != 0 && sc->subsystem != ec->subsystem) {
    return false;
  } else if (sc->devnode.length() != 0 && sc->devnode != ec->devnode) {
    return false;
  } else if (sc->devtype.length() != 0 && sc->devtype != ec->devtype) {
    return false;
  } else if (sc->driver.length() != 0 && sc->driver != ec->driver) {
    return false;
  }

  return true;
}
}
