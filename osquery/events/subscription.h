/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <boost/core/noncopyable.hpp>
#include <osquery/events/types.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/// Use a single placeholder for the EventContextRef passed to EventCallback.
using EventCallback = std::function<Status(const EventContextRef&,
                                           const SubscriptionContextRef&)>;

struct Subscription;
using SubscriptionRef = std::shared_ptr<Subscription>;

/// An EventPublisher must track every subscription added.
using SubscriptionVector = std::vector<SubscriptionRef>;

/**
 * @brief A Subscription is used to configure an EventPublisher and bind a
 * callback to a SubscriptionContext.
 *
 * A Subscription is the input to an EventPublisher when the EventPublisher
 * decides on the scope and details of the events it watches/generates.
 * An example includes a filesystem change event. A subscription would include
 * a path with optional recursion and attribute selectors as well as a callback
 * function to fire when an event for that path and selector occurs.
 *
 * A Subscription also functions to greatly scope an EventPublisher%'s work.
 * Using the same filesystem example and the Linux inotify subsystem a
 * Subscription limits the number of inode watches to only those requested by
 * appropriate EventSubscriber%s.
 * Note: EventSubscriber%s and Subscriptions can be configured by the osquery
 * user.
 *
 * Subscriptions are usually created with EventFactory members:
 *
 * @code{.cpp}
 *   EventFactory::addSubscription("MyEventPublisher", my_subscription_context);
 * @endcode
 */
struct Subscription : private boost::noncopyable {
 public:
  // EventSubscriber name.
  std::string subscriber_name;

  /// An EventPublisher%-specific SubscriptionContext.
  SubscriptionContextRef context;

  /// An EventSubscription member EventCallback method.
  EventCallback callback;

  explicit Subscription(std::string name);

  static SubscriptionRef create(const std::string& name);

  static SubscriptionRef create(const std::string& name,
                                const SubscriptionContextRef& mc,
                                EventCallback ec = nullptr);

 public:
  Subscription() = delete;
};

} // namespace osquery
