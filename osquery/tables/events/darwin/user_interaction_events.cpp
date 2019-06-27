/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/darwin/event_taps.h>
#include <osquery/registry_factory.h>

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
