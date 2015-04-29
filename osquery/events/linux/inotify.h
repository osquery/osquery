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

#include <map>
#include <vector>

#include <sys/inotify.h>
#include <sys/stat.h>

#include <osquery/events.h>

namespace osquery {

extern std::map<int, std::string> kMaskActions;

/**
 * @brief Subscriptioning details for INotifyEventPublisher events.
 *
 * This context is specific to INotifyEventPublisher. It allows the
 *subscriptioning
 * EventSubscriber to set a path (file or directory) and a limited action mask.
 * Events are passed to the subscriptioning EventSubscriber if they match the
 *context
 * path (or anything within a directory if the path is a directory) and if the
 * event action is part of the mask. If the mask is 0 then all actions are
 * passed to the EventSubscriber.
 */
struct INotifySubscriptionContext : public SubscriptionContext {
  /// Subscription the following filesystem path.
  std::string path;
  /// Limit the `inotify` actions to the subscriptioned mask (if not 0).
  uint32_t mask;
  /// Treat this path as a directory and subscription recursively.
  bool recursive;

  INotifySubscriptionContext() : mask(0), recursive(false) {}

  /**
   * @brief Helper method to map a string action to `inotify` action mask bit.
   *
   * This helper method will set the `mask` value for this SubscriptionContext.
   *
   * @param action The string action, a value in kMaskAction%s.
   */
  void requireAction(const std::string& action) {
    for (const auto& bit : kMaskActions) {
      if (action == bit.second) {
        mask = mask | bit.first;
      }
    }
  }
};

/**
 * @brief Event details for INotifyEventPublisher events.
 */
struct INotifyEventContext : public EventContext {
  /// The inotify_event structure if the EventSubscriber want to interact.
  std::shared_ptr<struct inotify_event> event;
  /// A string path parsed from the inotify_event.
  std::string path;
  /// A string action representing the event action `inotify` bit.
  std::string action;
  /// A no-op event transaction id.
  uint32_t transaction_id;

  INotifyEventContext() : event(nullptr), transaction_id(0) {}
};

typedef std::shared_ptr<INotifyEventContext> INotifyEventContextRef;
typedef std::shared_ptr<INotifySubscriptionContext>
    INotifySubscriptionContextRef;

// Thread-safe containers
typedef std::vector<int> DescriptorVector;
typedef std::map<std::string, int> PathDescriptorMap;
typedef std::map<int, std::string> DescriptorPathMap;

/**
 * @brief A Linux `inotify` EventPublisher.
 *
 * This EventPublisher allows EventSubscriber%s to subscription for Linux
 *`inotify` events.
 * Since these events are limited this EventPublisher will optimize the watch
 * descriptors, keep track of the usage, implement optimizations/priority
 * where possible, and abstract file system events to a path/action context.
 *
 * Uses INotifySubscriptionContext and INotifyEventContext for subscriptioning,
 *eventing.
 */
class INotifyEventPublisher
    : public EventPublisher<INotifySubscriptionContext, INotifyEventContext> {
  DECLARE_PUBLISHER("inotify");

 public:
  /// Create an `inotify` handle descriptor.
  Status setUp();
  void configure();
  /// Release the `inotify` handle descriptor.
  void tearDown();

  Status run();

  INotifyEventPublisher()
      : EventPublisher(), inotify_handle_(-1), last_restart_(-1) {}
  /// Check if the application-global `inotify` handle is alive.
  bool isHandleOpen() { return inotify_handle_ > 0; }

 private:
  INotifyEventContextRef createEventContextFrom(struct inotify_event* event);
  /// Check all added Subscription%s for a path.
  bool isPathMonitored(const std::string& path);
  /// Add an INotify watch (monitor) on this path.
  bool addMonitor(const std::string& path, bool recursive);
  /// Remove an INotify watch (monitor) from our tracking.
  bool removeMonitor(const std::string& path, bool force = false);
  bool removeMonitor(int watch, bool force = false);
  /// Given a SubscriptionContext and INotifyEventContext match path and action.
  bool shouldFire(const INotifySubscriptionContextRef& mc,
                  const INotifyEventContextRef& ec) const;
  /// Get the INotify file descriptor.
  int getHandle() { return inotify_handle_; }
  /// Get the number of actual INotify active descriptors.
  int numDescriptors() { return descriptors_.size(); }
  /// If we overflow, try and restart the monitor
  Status restartMonitoring();

  // Consider an event queue if separating buffering from firing/servicing.
  DescriptorVector descriptors_;
  PathDescriptorMap path_descriptors_;
  DescriptorPathMap descriptor_paths_;
  int inotify_handle_;
  int last_restart_;

 public:
  FRIEND_TEST(INotifyTests, test_inotify_optimization);
};
}
