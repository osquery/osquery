/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/events/darwin/event_taps.h"

namespace osquery {

class UserInteractionSubscriber
    : public EventSubscriber<EventTappingEventPublisher> {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

  Status Callback(const EventTappingEventContextRef& ec,
                  const EventTappingSubscriptionContextRef& sc);
};

REGISTER(UserInteractionSubscriber,
         "event_subscriber",
         "user_interaction_events");

void UserInteractionSubscriber::configure() {
  auto sc = createSubscriptionContext();
  subscribe(&UserInteractionSubscriber::Callback, sc);
}

Status UserInteractionSubscriber::Callback(
    const EventTappingEventContextRef& ec,
    const EventTappingSubscriptionContextRef& sc) {
  Row r;
  add(r);
  return Status(0);
}
} // namespace osquery
