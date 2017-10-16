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
  auto ec = createEventContext();
  EventFactory::fire<EventTappingEventPublisher>(ec);
  return event;
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
  if (run_loop_ != nullptr) {
    CFRunLoopStop(run_loop_);
    run_loop_ = nullptr;
  }
}

void EventTappingEventPublisher::restart() {
  stop();
  WriteLock lock(run_loop_mutex_);

  run_loop_ = CFRunLoopGetCurrent();
  CGEventMask eventMask = (1 << kCGEventKeyDown);
  CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap,
                                            kCGHeadInsertEventTap,
                                            kCGEventTapOptionListenOnly,
                                            eventMask,
                                            eventCallback,
                                            NULL);
  run_loop_source_ =
      CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
  CFRunLoopAddSource(run_loop_, run_loop_source_, kCFRunLoopCommonModes);
  CGEventTapEnable(eventTap, true);
  CFRelease(eventTap);
}

Status EventTappingEventPublisher::run() {
  restart();
  CFRunLoopRun();
  return Status(0);
}

bool EventTappingEventPublisher::shouldFire(
    const EventTappingSubscriptionContextRef& mc,
    const EventTappingEventContextRef& ec) const {
  return true;
}
}
