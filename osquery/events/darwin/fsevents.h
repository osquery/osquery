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

extern std::map<FSEventStreamEventFlags, std::string> kMaskActions;

struct FSEventsSubscriptionContext : public SubscriptionContext {
  /// Subscription the following filesystem path.
  std::string path;
  /// Limit the FSEvents actions to the subscriptioned mask (if not 0).
  FSEventStreamEventFlags mask;
  // A no-op since FSEvent subscriptions are always recursive.
  bool recursive;

  void requireAction(std::string action) {
    for (const auto& bit : kMaskActions) {
      if (action == bit.second) {
        mask = mask & bit.first;
      }
    }
  }

  FSEventsSubscriptionContext() : mask(0), recursive(false) {}
};

struct FSEventsEventContext : public EventContext {
  ConstFSEventStreamRef fsevent_stream;
  FSEventStreamEventFlags fsevent_flags;
  FSEventStreamEventId transaction_id;

  std::string path;
  std::string action;

  FSEventsEventContext() : fsevent_flags(0), transaction_id(0) {}
};

typedef std::shared_ptr<FSEventsEventContext> FSEventsEventContextRef;
typedef std::shared_ptr<FSEventsSubscriptionContext>
    FSEventsSubscriptionContextRef;

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
  void configure();
  void tearDown();

  // Entrypoint to the run loop
  Status run();
  // Callin for stopping the streams/run loop.
  void end();

 public:
  /// FSEvents registers a client callback instead of using a select/poll loop.
  static void Callback(ConstFSEventStreamRef fsevent_stream,
                       void* callback_info,
                       size_t num_events,
                       void* event_paths,
                       const FSEventStreamEventFlags fsevent_flags[],
                       const FSEventStreamEventId fsevent_ids[]);

 public:
  FSEventsEventPublisher() : EventPublisher() {
    stream_started_ = false;
    stream_ = nullptr;
    run_loop_ = nullptr;
  }

  bool shouldFire(const FSEventsSubscriptionContextRef& mc,
                  const FSEventsEventContextRef& ec) const;

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
  FSEventStreamRef stream_;
  bool stream_started_;
  std::set<std::string> paths_;

 private:
  CFRunLoopRef run_loop_;

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
