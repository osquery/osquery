/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/dispatcher.h>
#include <osquery/ev2/event.h>
#include <osquery/ev2/buffered_subscription.h>
#include <osquery/ev2/simple_publisher.h>
#include <osquery/logger.h>

#include <set>
#include <string>

#include <libudev.h>
#include <pthread.h>
#include <signal.h>

namespace osquery {
namespace evgen {

class UdevEvent : public ev2::Event {
 public:
  enum class Action {
    Add = 1,
    Remove = 2,
    Change = 3,
  };

  static Action actionFromString(const std::string& action_str);
  static const std::string actionToString(Action action);

 public:
  explicit UdevEvent(
      ev2::EventId id,
      ev2::EventTime time,
      Action action,
      const std::string& subsystem,
      const std::string& devnode,
      const std::string& devtype,
      const std::string& driver);
  ~UdevEvent() = default;

 public:
  const Action action;
  const std::string subsystem;
  const std::string devnode;
  const std::string devtype;
  const std::string driver;
};

class UdevSubscription : public ev2::BufferedSubscription<UdevEvent> {
 public:
  explicit UdevSubscription(
      const std::string& subscriber,
      const std::set<UdevEvent::Action>& actions);
  explicit UdevSubscription(
      const std::string& subscriber);
  ~UdevSubscription() = default;

 public:
  const std::set<UdevEvent::Action>& getActions();

 private:
  std::set<UdevEvent::Action> actions_;
};

class UdevPublisher
  : public ev2::SimplePublisher<UdevSubscription>
  , public InternalRunnable {
 public:
  UdevPublisher();
  ~UdevPublisher();

 private:
  void start() override;
  void stop() override;

  void free();

  UdevEvent getEventFromDevice(struct udev_device* device);

 private:
  struct udev* udev_;
  struct udev_monitor* monitor_;
  int fd_;

  std::mutex mutex_;
  pthread_t thread_;

  std::atomic<bool> stop_;
  std::atomic<bool> running_;
};

class UdevPublisherException : public std::runtime_error {
 public:
  UdevPublisherException(const std::string& msg);
};

} // namespace evgen
} // namespace osquery
