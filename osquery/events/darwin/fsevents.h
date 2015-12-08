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
#include <string>
#include <vector>

#include <boost/make_shared.hpp>

#include <CoreServices/CoreServices.h>

#include <osquery/events.h>
#include <osquery/status.h>

namespace osquery {

struct FSEventsSubscriptionContext : public SubscriptionContext {
 public:
  /// Subscription the following filesystem path.
  std::string path;

  /// Limit the FSEvents actions to the subscriptioned mask (if not 0).
  FSEventStreamEventFlags mask{0};

  /// A pattern with a recursive match was provided.
  bool recursive{false};

  /// Save the category this path originated form within the config.
  std::string category;

  /// Append an action.
  void requireAction(const std::string& action);

 private:
  /**
   * @brief The existing configure-time discovered path.
   *
   * The FSEvents publisher expects paths from a configuration to contain
   * filesystem globbing wildcards, as opposed to SQL wildcards. It also expects
   * paths to be canonicalized up to the first wildcard. To FSEvents a double
   * wildcard, meaning recursive, is a watch on the base path string. A single
   * wildcard means the same watch but a preserved globbing pattern, which is
   * applied at event-fire time to limit subscriber results.
   *
   * This backup will allow post-fire subscriptions to match. It will also allow
   * faster reconfigures by not performing string manipulation twice.
   */
  std::string discovered_;

  /// A configure-time pattern was expanded to match absolute paths.
  bool recursive_match{false};

 private:
  friend class FSEventsEventPublisher;
};

struct FSEventsEventContext : public EventContext {
 public:
  ConstFSEventStreamRef fsevent_stream{nullptr};
  FSEventStreamEventFlags fsevent_flags{0};
  FSEventStreamEventId transaction_id{0};

  std::string path;
  std::string action;
};

using FSEventsEventContextRef = std::shared_ptr<FSEventsEventContext>;
using FSEventsSubscriptionContextRef =
    std::shared_ptr<FSEventsSubscriptionContext>;

/**
 * @brief An osquery EventPublisher for the Apple FSEvents notification API.
 *
 * This exposes a lightweight filesystem eventing type by wrapping Apple's
 * preferred implementation of FSEvents handling.
 *
 */
class FSEventsEventPublisher
    : public EventPublisher<FSEventsSubscriptionContext, FSEventsEventContext> {
  DECLARE_PUBLISHER("fsevents");

 public:
  /// Called when configuration is loaded or updates occur.
  void configure() override;

  /// Another alias for `::end` or `::stop`.
  void tearDown() override;

  /// Entrypoint to the run loop
  Status run() override;

  /// Callin for stopping the streams/run loop.
  void end() override { stop(); }

  /// Delete all paths from prior configuration.
  void removeSubscriptions() override;

 public:
  /// FSEvents registers a client callback instead of using a select/poll loop.
  static void Callback(ConstFSEventStreamRef fsevent_stream,
                       void* callback_info,
                       size_t num_events,
                       void* event_paths,
                       const FSEventStreamEventFlags fsevent_flags[],
                       const FSEventStreamEventId fsevent_ids[]);

 public:
  bool shouldFire(const FSEventsSubscriptionContextRef& mc,
                  const FSEventsEventContextRef& ec) const override;

 private:
  // Restart the run loop.
  void restart();

  // Stop the stream and the run loop.
  void stop();

  // Cause the FSEvents to flush kernel-buffered events.
  void flush(bool async = false);

 private:
  // Check if the stream (and run loop) are running.
  bool isStreamRunning();

  // Count the number of subscriptioned paths.
  size_t numSubscriptionedPaths();

 private:
  /// Local reference to the start, stop, restart event stream.
  FSEventStreamRef stream_{nullptr};

  /// Has the FSEvents run loop and stream been started.
  bool stream_started_{false};

  /// Set of paths to monitor, determined by a configure step.
  std::set<std::string> paths_;

  CFRunLoopRef run_loop_{nullptr};

 private:
  friend class FSEventsTests;
  FRIEND_TEST(FSEventsTests, test_register_event_pub);
  FRIEND_TEST(FSEventsTests, test_fsevents_add_subscription_missing_path);
  FRIEND_TEST(FSEventsTests, test_fsevents_add_subscription_success);
  FRIEND_TEST(FSEventsTests, test_fsevents_run);
  FRIEND_TEST(FSEventsTests, test_fsevents_fire_event);
  FRIEND_TEST(FSEventsTests, test_fsevents_event_action);
};
}
