/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <poll.h>

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/events/linux/udev.h"

namespace osquery {

static const int kUdevMLatency = 200;

REGISTER(UdevEventPublisher, "event_publisher", "udev");

Status UdevEventPublisher::setUp() {
  // The Setup and Teardown workflows should be protected against races.
  // Just in case let's protect the publisher's resources.
  WriteLock lock(mutex_);

  // Create the udev object.
  handle_ = udev_new();
  if (handle_ == nullptr) {
    return Status(1, "Could not create udev object.");
  }

  // Set up the udev monitor before scanning/polling.
  monitor_ = udev_monitor_new_from_netlink(handle_, "udev");
  if (monitor_ == nullptr) {
    udev_unref(handle_);
    handle_ = nullptr;
    return Status(1, "Could not create udev monitor.");
  }

  udev_monitor_enable_receiving(monitor_);
  return Status(0, "OK");
}

void UdevEventPublisher::tearDown() {
  WriteLock lock(mutex_);
  if (monitor_ != nullptr) {
    udev_monitor_unref(monitor_);
    monitor_ = nullptr;
  }

  if (handle_ != nullptr) {
    udev_unref(handle_);
    handle_ = nullptr;
  }
}

Status UdevEventPublisher::run() {
  int fd = 0;

  {
    WriteLock lock(mutex_);
    if (monitor_ == nullptr) {
      return Status(1);
    }
    fd = udev_monitor_get_fd(monitor_);

  struct pollfd fds[1];
  fds[0].fd = fd;
  fds[0].events = POLLIN;

  int selector = ::poll(fds, 1, 1000);
  if (selector == -1 && errno != EINTR && errno != EAGAIN) {
    LOG(ERROR) << "Could not read udev monitor";
    return Status(1, "udev monitor failed.");
  }

  if (selector == 0 || !(fds[0].revents & POLLIN)) {
    // Read timeout.
    return Status(0, "Finished");
  }

    WriteLock lock(mutex_);
    struct udev_device* device = udev_monitor_receive_device(monitor_);
    if (device == nullptr) {
      LOG(ERROR) << "udev monitor returned invalid device";
      return Status(1, "udev monitor failed.");
    }

    auto ec = createEventContextFrom(device);
    fire(ec);

    udev_device_unref(device);
  }

  pauseMilli(kUdevMLatency);
  return Status(0, "OK");
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

UdevEventContextRef UdevEventPublisher::createEventContextFrom(
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
                                    const UdevEventContextRef& ec) const {
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
