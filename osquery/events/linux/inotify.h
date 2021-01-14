/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <vector>

#include <sys/inotify.h>
#include <sys/stat.h>

#include <osquery/events/eventpublisher.h>
#include <osquery/events/pathset.h>
#include <osquery/events/subscription.h>

namespace osquery {

extern std::map<int, std::string> kMaskActions;

extern const uint32_t kFileDefaultMasks;
extern const uint32_t kFileAccessMasks;

// INotifySubscriptionContext containers
using PathDescriptorMap = std::map<std::string, int>;
using DescriptorPathMap = std::map<int, std::string>;
using PathStatusChangeTimeMap = std::map<std::string, time_t>;

/**
 * @brief Subscription details for INotifyEventPublisher events.
 *
 * This context is specific to INotifyEventPublisher. It allows the
 * subscribing EventSubscriber to set a path (file or directory) and a
 * limited action mask.
 * Events are passed to the EventSubscriber if they match the context
 * path (or anything within a directory if the path is a directory) and if the
 * event action is part of the mask. If the mask is 0 then all actions are
 * passed to the EventSubscriber.
 */
struct INotifySubscriptionContext : public SubscriptionContext {
  /// Subscription the following filesystem path.
  std::string path;

  /// original path, read from config
  std::string opath;

  /// Limit the `inotify` actions to the subscription mask (if not 0).
  uint32_t mask{0};

  /// Treat this path as a directory and subscription recursively.
  bool recursive{false};

  /// Save the category this path originated form within the config.
  std::string category;

  /// Lazy deletion of a subscription.
  bool mark_for_deletion{false};

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

 private:
  /// A configure-time pattern was expanded to match absolute paths.
  bool recursive_match{false};

  /// Map of inotify watch file descriptor to watched path string.
  DescriptorPathMap descriptor_paths_;

  /// Map of path and status change time of file/directory.
  PathStatusChangeTimeMap path_sc_time_;

 private:
  friend class INotifyEventPublisher;
};

/// Overloaded '==' operator, to check if two inotify subscriptions are same.
inline bool operator==(const INotifySubscriptionContext& lsc,
                       const INotifySubscriptionContext& rsc) {
  return ((lsc.category == rsc.category) && (lsc.opath == rsc.opath));
}

using INotifySubscriptionContextRef =
    std::shared_ptr<INotifySubscriptionContext>;

/**
 * @brief Event details for INotifyEventPublisher events.
 */
struct INotifyEventContext : public EventContext {
  /// The inotify_event structure if the EventSubscriber want to interact.
  std::unique_ptr<struct inotify_event> event{nullptr};

  /// A string path parsed from the inotify_event.
  std::string path;

  /// A string action representing the event action `inotify` bit.
  std::string action;

  /// A no-op event transaction id.
  uint32_t transaction_id{0};

  /// This event ctx belongs to isub_ctx
  INotifySubscriptionContextRef isub_ctx;
};

using INotifyEventContextRef = std::shared_ptr<INotifyEventContext>;

// Publisher container
using DescriptorINotifySubCtxMap = std::map<int, INotifySubscriptionContextRef>;

using ExcludePathSet = PathSet<patternedPath>;

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
  //@param unit_test publisher is instantiated for unit test.
  INotifyEventPublisher(bool unit_test = false)
      : inotify_sanity_check(unit_test) {}

  virtual ~INotifyEventPublisher() {
    tearDown();
  }

  /// Create an `inotify` handle descriptor.
  Status setUp() override;

  /// The configuration finished loading or was updated.
  void configure() override;

  /// Release the `inotify` handle descriptor.
  void tearDown() override;

  /// The calling for beginning the thread's run loop.
  Status run() override;

  /// Mark for delete, subscriptions.
  void removeSubscriptions(const std::string& subscriber) override;

  /// Only add the subscription, if it not already part of subscription list.
  Status addSubscription(const SubscriptionRef& subscription) override;

 private:
  /// Helper/specialized event context creation.
  INotifyEventContextRef createEventContextFrom(
      struct inotify_event* event) const;

  /// Check if the application-global `inotify` handle is alive.
  bool isHandleOpen() const {
    return inotify_handle_ > 0;
  }

  /// Check all added Subscription%s for a path.
  /// Used for sanity check from unit test(s).
  bool isPathMonitored(const std::string& path) const;

  /**
   * @brief Add an INotify watch (monitor) on this path.
   *
   * Check if a given path is already monitored (perhaps the parent path) has
   * and existing monitor and this is a non-directory leaf? On success the
   * file descriptor is stored for lookup when events fire.
   *
   * A recursive flag will tell addMonitor to enumerate all subdirectories
   * recursively and add monitors to them.
   *
   * @param path complete (non-glob) canonical path to monitor.
   * @param subscription context tracking the path.
   * @param recursive perform a single recursive search of subdirectories.
   * @param add_watch (testing only) should an inotify watch be created.
   * @return success if the inotify watch was created.
   */
  bool addMonitor(const std::string& path,
                  INotifySubscriptionContextRef& isc,
                  uint32_t mask,
                  bool recursive,
                  bool add_watch = true);

  /**
   * Some decision making code refactored in needMonitoring before calling
   * addMonitor in the context of monitorSubscription.
   * Decision to call addMonitor from the context of monitorSubscription
   * is done based on the status change time of file/directory, since
   * creation time is not available on linux.
   */
  bool needMonitoring(const std::string& path,
                      INotifySubscriptionContextRef& isc,
                      uint32_t mask,
                      bool recursive,
                      bool add_watch);

  /// Helper method to parse a subscription and add an equivalent monitor.
  bool monitorSubscription(INotifySubscriptionContextRef& sc,
                           bool add_watch = true);

  /// Build the set of excluded paths for which events are not to be propagated.
  void buildExcludePathsSet();

  /// Remove an INotify watch (monitor) from our tracking.
  bool removeMonitor(int watch, bool force = false, bool batch_del = false);

  /// Given a SubscriptionContext and INotifyEventContext match path and action.
  bool shouldFire(const INotifySubscriptionContextRef& mc,
                  const INotifyEventContextRef& ec) const override;

  /// Get the INotify file descriptor.
  int getHandle() const {
    return inotify_handle_;
  }

  /// Get the number of actual INotify active descriptors.
  size_t numDescriptors() const {
    return descriptor_inosubctx_.size();
  }

  /// If we overflow, try to read more events from OS at time.
  void handleOverflow();

  /// Map of watched path string to inotify watch file descriptor.
  /// Used for sanity check from unit test(s).
  PathDescriptorMap path_descriptors_;

  /// Map of inotify watch file descriptor to subscription context.
  DescriptorINotifySubCtxMap descriptor_inosubctx_;

  /// Events pertaining to these paths not to be propagated.
  ExcludePathSet exclude_paths_;

  /// The inotify file descriptor handle.
  std::atomic<int> inotify_handle_{-1};

  /// Time in seconds of the last inotify overflow.
  std::atomic<int> last_overflow_{-1};

  /// Tracks how many events to be received from OS.
  size_t inotify_events_{16};

  /// Enable for sanity check from unit test(s).
  bool inotify_sanity_check{false};

  /**
   * @brief Scratch space for reading INotify responses.
   *
   * We place this here, and include a mutex to do heap/lazy allocation of the
   * near-3k buffer when the publisher loads. This reduces the need to stack
   * allocate a local buffer every 200mils and also improves the eventless-case.
   *
   * Allocated during setUp, removed in tearDown, protected by scratch_mutex_.
   */
  char* scratch_{nullptr};

  /// Access to path and descriptor mappings.
  mutable Mutex path_mutex_;

  /// Access the Inofity response scratch space.
  mutable Mutex scratch_mutex_;

 public:
  friend class INotifyTests;
  FRIEND_TEST(INotifyTests, test_inotify_init);
  FRIEND_TEST(INotifyTests, test_inotify_optimization);
  FRIEND_TEST(INotifyTests, DISABLED_test_inotify_recursion);
  FRIEND_TEST(INotifyTests, test_inotify_match_subscription);
  FRIEND_TEST(INotifyTests, test_inotify_embedded_wildcards);
};
}
