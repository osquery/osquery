/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/eventfactory.h>
#include <osquery/events/eventpublisherplugin.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>

namespace osquery {

CREATE_REGISTRY(EventPublisherPlugin, "event_publisher");

const std::string EventPublisherPlugin::type() const {
  return getName();
}

bool EventPublisherPlugin::isEnding() const {
  return ending_;
}

void EventPublisherPlugin::isEnding(bool ending) {
  ending_ = ending;
}

bool EventPublisherPlugin::hasStarted() const {
  return started_;
}

void EventPublisherPlugin::hasStarted(bool started) {
  started_ = started;
}

size_t EventPublisherPlugin::restartCount() const {
  return restart_count_;
}

bool EventPublisherPlugin::interrupted() {
  // Warning: deprecated. Use isEnding() instead
  return false;
}

EventContextID EventPublisherPlugin::numEvents() const {
  return next_ec_id_.load();
}

size_t EventPublisherPlugin::numSubscriptions() {
  ReadLock lock(subscription_lock_);
  return subscriptions_.size();
}

void EventPublisherPlugin::fire(const EventContextRef& ec, EventTime time) {
  if (isEnding()) {
    // Cannot emit/fire while ending
    return;
  }

  EventContextID ec_id = 0;
  ec_id = next_ec_id_.fetch_add(1);

  // Fill in EventContext ID and time if needed.
  if (ec != nullptr) {
    ec->id = ec_id;
    if (ec->time == 0) {
      if (time == 0) {
        time = getTime();
      }
      ec->time = time;
    }
  }

  ReadLock lock(subscription_lock_);
  for (const auto& subscription : subscriptions_) {
    auto es = EventFactory::getEventSubscriber(subscription->subscriber_name);
    if (es != nullptr && es->state() == EventState::EVENT_RUNNING) {
      fireCallback(subscription, ec);
    }
  }
}

uint64_t EventPublisherPlugin::getTime() const {
  return getUnixTime();
}

void EventPublisherPlugin::configure() {}

Status EventPublisherPlugin::setUp() {
  return Status::success();
}

void EventPublisherPlugin::tearDown() {}

Status EventPublisherPlugin::run() {
  return Status(1, "No run loop required");
}

void EventPublisherPlugin::stop() {}

Status EventPublisherPlugin::call(const PluginRequest&, PluginResponse&) {
  return Status(0);
}

Status EventPublisherPlugin::addSubscription(
    const SubscriptionRef& subscription) {
  // The publisher threads may be running and if they fire events the list of
  // subscriptions will be walked.
  WriteLock lock(subscription_lock_);
  subscriptions_.push_back(subscription);
  return Status(0);
}

void EventPublisherPlugin::removeSubscriptions(const std::string& subscriber) {
  // See addSubscription for details on the critical section.
  WriteLock lock(subscription_lock_);
  auto end =
      std::remove_if(subscriptions_.begin(),
                     subscriptions_.end(),
                     [&subscriber](const SubscriptionRef& subscription) {
                       return (subscription->subscriber_name == subscriber);
                     });
  subscriptions_.erase(end, subscriptions_.end());
}

} // namespace osquery
