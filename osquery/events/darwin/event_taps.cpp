/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/flags.h>

#include "osquery/events/darwin/event_taps.h"

namespace osquery {

/// Flag that turns the eventing system for event taps on or off
FLAG(bool,
     enable_keyboard_events,
     false,
     "Enable listening for keyboard events");

REGISTER(EventTappingEventPublisher, "event_publisher", "event_tapping");

CGEventRef EventTappingEventPublisher::eventCallback(CGEventTapProxy proxy,
                                                     CGEventType type,
                                                     CGEventRef event,
                                                     void* refcon) {
  EventFactory::fire<EventTappingEventPublisher>(createEventContext());
  // If you change from listenOnly, return event or you will drop all events
  return nullptr;
}

EventTappingEventPublisher::~EventTappingEventPublisher() {
  tearDown();
}

Status EventTappingEventPublisher::setUp() {
  if (!FLAGS_enable_keyboard_events) {
    return Status(1, "Publisher disabled via configuration");
  }
  return Status(0);
}

void EventTappingEventPublisher::tearDown() {
  stop();
}

void EventTappingEventPublisher::stop() {
  WriteLock lock(run_loop_mutex_);

  if (run_loop_source_ != nullptr) {
    CFRunLoopRemoveSource(run_loop_, run_loop_source_, kCFRunLoopCommonModes);
    CFRelease(run_loop_source_);
    run_loop_source_ = nullptr;
  }

  if (event_tap_ != nullptr) {
    CGEventTapEnable(event_tap_, false);
    CFRelease(event_tap_);
    event_tap_ = nullptr;
  }

  if (run_loop_ != nullptr) {
    CFRunLoopStop(run_loop_);
    run_loop_ = nullptr;
  }
}

Status EventTappingEventPublisher::restart() {
  stop();
  WriteLock lock(run_loop_mutex_);

  run_loop_ = CFRunLoopGetCurrent();
  event_tap_ = CGEventTapCreate(kCGSessionEventTap,
                                kCGHeadInsertEventTap,
                                kCGEventTapOptionListenOnly,
                                (1 << kCGEventKeyDown),
                                eventCallback,
                                nullptr);
  if (event_tap_ == nullptr) {
    run_loop_ = nullptr;
    return Status(1, "Could not create event tap");
  }
  run_loop_source_ =
      CFMachPortCreateRunLoopSource(kCFAllocatorDefault, event_tap_, 0);
  CFRunLoopAddSource(run_loop_, run_loop_source_, kCFRunLoopCommonModes);
  CGEventTapEnable(event_tap_, true);
  return Status(0);
}

Status EventTappingEventPublisher::run() {
  Status s = restart();
  if (s.ok()) {
    CFRunLoopRun();
  }
  return s;
}

bool EventTappingEventPublisher::shouldFire(
    const EventTappingSubscriptionContextRef& mc,
    const EventTappingEventContextRef& ec) const {
  return true;
}
}
