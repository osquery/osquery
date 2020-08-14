/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/events/darwin/event_taps.h"

namespace osquery {

/// Flag that turns the keyboard events on
FLAG(bool,
     enable_keyboard_events,
     false,
     "Enable listening for keyboard events");

/// Flag that turns the mouse events on
FLAG(bool, enable_mouse_events, false, "Enable listening for mouse events");

REGISTER(EventTappingEventPublisher,
         "event_publisher",
         "user_interaction_publisher");

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
  if (!FLAGS_enable_keyboard_events && !FLAGS_enable_mouse_events) {
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

  CGEventMask mask = kCGEventNull;
  if (FLAGS_enable_keyboard_events) {
    mask |= 1 << kCGEventKeyDown;
  }

  if (FLAGS_enable_mouse_events) {
    mask |= 1 << kCGEventLeftMouseDown;
  }

  event_tap_ = CGEventTapCreate(kCGSessionEventTap,
                                kCGHeadInsertEventTap,
                                kCGEventTapOptionListenOnly,
                                mask,
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
