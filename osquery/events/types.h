/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/core/noncopyable.hpp>

namespace osquery {

using EventContextID = uint64_t;
using EventTime = uint64_t;
using EventRecord = std::pair<std::string, EventTime>;
using EventID = std::uint64_t;
using EventIDList = std::vector<EventID>;
using EventIndex = std::map<EventTime, EventIDList>;

/**
 * @brief An EventSubscriber EventCallback method will receive an EventContext.
 *
 * The EventContext contains the event-related data supplied by an
 * EventPublisher when the event occurs. If a subscribing EventSubscriber
 * would be called for the event, the EventSubscriber%'s EventCallback is
 * passed an EventContext.
 */
struct EventContext : private boost::noncopyable {
  virtual ~EventContext() {}

  /// An unique counting ID specific to the EventPublisher%'s fired events.
  EventContextID id{0};

  /// The time the event occurred, as determined by the publisher.
  EventTime time{0};
};

using EventContextRef = std::shared_ptr<EventContext>;

/**
 * @brief An EventPublisher will define a SubscriptionContext for
 * EventSubscriber%s to use.
 *
 * Most EventPublisher%s will require specific information for interacting with
 * an OS to receive events. The SubscriptionContext contains information the
 * EventPublisher will use to register OS API callbacks, create
 * subscriptioning/listening handles, etc.
 *
 * Linux `inotify` should implement a SubscriptionContext that subscribes
 * filesystem events based on a filesystem path. `libpcap` will subscribe on
 * networking protocols at various stacks. Process creation may subscribe on
 * process name, parent pid, etc.
 */
struct SubscriptionContext : private boost::noncopyable {
  virtual ~SubscriptionContext(){};
};

using SubscriptionContextRef = std::shared_ptr<SubscriptionContext>;

class EventPublisherPlugin;
using EventPublisherRef = std::shared_ptr<EventPublisherPlugin>;

class EventSubscriberPlugin;
using EventSubscriberRef = std::shared_ptr<EventSubscriberPlugin>;
} // namespace osquery
