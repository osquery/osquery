/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <ApplicationServices/ApplicationServices.h>

#include <osquery/flags.h>

#include "osquery/events/darwin/event_taps.h"

namespace osquery {

/// Flag that turns the eventing system for event taps on or off
FLAG(bool,
     disable_event_tapping,
     true,
     "Disable receiving and subscribing to events from the event taps "
     "subsystem");

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
  if (FLAGS_disable_event_tapping) {
    return Status(1, "Publisher disabled via configuration");
  }
  return Status(0);
}

void EventTappingEventPublisher::configure() {
  WriteLock lock(mutex_);
  restart();
}

void EventTappingEventPublisher::tearDown() {
  stop();

  WriteLock lock(mutex_);
  run_loop_ = nullptr;
}

void EventTappingEventPublisher::stop() {
  WriteLock lock(mutex_);

  if (run_loop_source_ != nullptr) {
    CFRunLoopRemoveSource(
        CFRunLoopGetCurrent(), run_loop_source_, kCFRunLoopCommonModes);
    run_loop_source_ = nullptr;
  }
  if (run_loop_ != nullptr) {
    CFRunLoopStop(run_loop_);
  }
}

void EventTappingEventPublisher::restart() {
  if (run_loop_ == nullptr) {
    return;
  }
  stop();
  WriteLock lock(mutex_);
  CGEventMask eventMask = (1 << kCGEventKeyDown);
  CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap,
                                            kCGHeadInsertEventTap,
                                            kCGEventTapOptionListenOnly,
                                            eventMask,
                                            eventCallback,
                                            NULL);
  run_loop_source_ =
      CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
  CFRunLoopAddSource(
      CFRunLoopGetCurrent(), run_loop_source_, kCFRunLoopCommonModes);
  CGEventTapEnable(eventTap, true);
}

Status EventTappingEventPublisher::run() {
  if (run_loop_ == nullptr) {
    run_loop_ = CFRunLoopGetCurrent();
    restart();
  }

  CFRunLoopRun();
  return Status(0);
}

bool EventTappingEventPublisher::shouldFire(
    const EventTappingSubscriptionContextRef& mc,
    const EventTappingEventContextRef& ec) const {
  return true;
}
}
