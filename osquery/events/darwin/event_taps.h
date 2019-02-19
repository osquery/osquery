/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <ApplicationServices/ApplicationServices.h>

#include <osquery/events.h>

namespace osquery {

struct EventTappingSubscriptionContext : public SubscriptionContext {};
struct EventTappingEventContext : public EventContext {};

using EventTappingEventContextRef = std::shared_ptr<EventTappingEventContext>;
using EventTappingSubscriptionContextRef =
    std::shared_ptr<EventTappingSubscriptionContext>;

/// This is a dispatched service that handles published EventTapping events.
class EventTappingConsumerRunner;

class EventTappingEventPublisher
    : public EventPublisher<EventTappingSubscriptionContext,
                            EventTappingEventContext> {
  DECLARE_PUBLISHER("event_tapping");
 public:
  Status setUp() override;

  void tearDown() override;

  void stop() override;

  Status run() override;

  Status restart();

  EventTappingEventPublisher(
      const std::string& name = "EventTappingEventPublisher")
      : EventPublisher() {
    runnable_name_ = name;
  }

  ~EventTappingEventPublisher() override final;

  static CGEventRef eventCallback(CGEventTapProxy proxy,
                                  CGEventType type,
                                  CGEventRef event,
                                  void* refcon);

 private:
  /// Apply normal subscription to event matching logic.
  bool shouldFire(const EventTappingSubscriptionContextRef& mc,
                  const EventTappingEventContextRef& ec) const override;

  /// This publisher thread's runloop.
  CFRunLoopSourceRef run_loop_source_{nullptr};
  CFRunLoopRef run_loop_{nullptr};
  CFMachPortRef event_tap_{nullptr};

  /// Storage/container operations protection mutex.
  mutable Mutex run_loop_mutex_;
};
} // namespace osquery
