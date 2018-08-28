/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include "udev.h"

#include <stdexcept>
#include <typeinfo>

#include <poll.h>
#include <pthread.h>

namespace osquery {
namespace evgen {

UdevEvent::UdevEvent(
    ev2::EventId _id,
    ev2::EventTime _time,
    UdevEvent::Action _action,
    const std::string& _subsystem,
    const std::string& _devnode,
    const std::string& _devtype,
    const std::string& _driver)
  : Event(_id, _time)
  , action(_action)
  , subsystem(_subsystem)
  , devnode(_devnode)
  , devtype(_devtype)
  , driver(_driver)
{
}


UdevSubscription::UdevSubscription(
    const std::string& subscriber,
    const std::set<UdevEvent::Action>& actions)
  : BufferedSubscription(subscriber, typeid(UdevPublisher))
  , actions_(actions)
{
}

UdevSubscription::UdevSubscription(
    const std::string& subscriber)
  : BufferedSubscription(subscriber, typeid(UdevPublisher))
  , actions_({
      UdevEvent::Action::Add,
      UdevEvent::Action::Remove,
      UdevEvent::Action::Change,
      })
{
}

const std::set<UdevEvent::Action>& UdevSubscription::getActions()
{
  return actions_;
}

UdevEvent::Action UdevEvent::actionFromString(const std::string& action_str)
{
  if (action_str == "add") {
    return Action::Add;
  } else if (action_str == "remove") {
    return Action::Remove;
  } else if (action_str == "change") {
    return Action::Change;
  } else {
    /* FIXME: return Expected */
    throw std::runtime_error("Invalid action");
  }
}

const std::string UdevEvent::actionToString(UdevEvent::Action action)
{
  switch (action) {
    case Action::Add:
      return "add";
    case Action::Remove:
      return "remove";
    case Action::Change:
      return "change";
  }
}

UdevPublisher::UdevPublisher()
  : SimplePublisher("udev")
  , InternalRunnable("UdevPublisher")
  , udev_(nullptr)
  , monitor_(nullptr)
  , fd_(0)
  , stop_(false)
  , running_(false)
{
  udev_ = udev_new();
  if (udev_ == nullptr) {
    free();
    throw UdevPublisherException("Failed to open udev handle");
  }

  monitor_ = udev_monitor_new_from_netlink(udev_, "udev");
  if (monitor_ == nullptr) {
    free();
    throw UdevPublisherException("Failed to open udev monitor");
  }

  fd_ = udev_monitor_get_fd(monitor_);
  if (fd_ < 0) {
    free();
    throw UdevPublisherException("Failed to get udev monitor fd");
  }

  int rc = udev_monitor_enable_receiving(monitor_);
  if (rc < 0) {
    free();
    throw UdevPublisherException("Failed to enable udev monitor");
  }
}

UdevPublisher::~UdevPublisher()
{
  free();
}

void UdevPublisher::start()
{
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
      return;
    }

    thread_ = pthread_self();
    running_ = true;
  }

  LOG(INFO) << "Started udev publisher run loop";

  struct pollfd fds[1] = {
    {
      .fd = fd_,
      .events = POLLIN,
    }
  };

  while (!stop_) {
    int rc = ::poll(fds, 1, -1);

    /* Check poll errors */
    if (rc < 0) {
      if (!(errno == EINTR || errno == EAGAIN)) {
        LOG(ERROR)
          << "poll failed on udev publisher run loop with error: "
          << std::to_string(rc);
        stop_ = true;
      }

      continue;
    }

    /* Check event errors */
    if (!(fds[0].revents & POLLIN)) {
      LOG(ERROR)
        << "poll of udev fd on udev publisher run loop return error event";
      stop_ = true;
      continue;
    }

    /* Get the device */
    struct udev_device* device = udev_monitor_receive_device(monitor_);
    /* Check device is valid */
    if (device == nullptr) {
      LOG(ERROR) << "Failed to receive device from udev";
      continue;
    }

    UdevEvent event = getEventFromDevice(device);
    udev_device_unref(device);

    for (const auto& sub : subs_) {
      if (sub->getActions().count(event.action)) {
        sub->enqueue(event);
      }
    }
  }

  LOG(INFO) << "Stopped udev publisher run loop";

  stop_ = false;
  running_ = false;
}

void UdevPublisher::stop()
{
  std::lock_guard<std::mutex> lock(mutex_);

  if (!running_ || stop_) {
    return;
  }

  stop_ = true;
  pthread_kill(thread_, SIGUSR1);
}

void UdevPublisher::free()
{
  if (monitor_) {
    udev_monitor_unref(monitor_);
  }

  if (udev_) {
    udev_unref(udev_);
  }
}

UdevEvent UdevPublisher::getEventFromDevice(struct udev_device* device)
{
  const char* action_str = udev_device_get_action(device);
  const char* subsystem = udev_device_get_subsystem(device);
  const char* devnode = udev_device_get_devnode(device);
  const char* devtype = udev_device_get_devtype(device);
  const char* driver = udev_device_get_driver(device);

  UdevEvent::Action action = UdevEvent::actionFromString(action_str);

  return UdevEvent(
      next_id_++,
      std::chrono::system_clock::now(),
      action,
      subsystem ? subsystem : "",
      devnode ? devnode : "",
      devtype ? devtype : "",
      driver ? driver : "");
}

UdevPublisherException::UdevPublisherException(const std::string& msg)
  : std::runtime_error(msg)
{
}

} // namespace evgen
} // namespace osquery
