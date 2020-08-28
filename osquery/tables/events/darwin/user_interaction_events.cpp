/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/darwin/event_taps.h>
#include <osquery/registry/registry_factory.h>

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
