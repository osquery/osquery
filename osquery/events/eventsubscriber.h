/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventfactory.h>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriberplugin.h>

namespace osquery {

/**
 * @brief An interface binding Subscriptions, event response, and table
 *generation.
 *
 * Use the EventSubscriber interface when adding event subscriptions and
 * defining callin functions. The EventCallback is usually a member function
 * for an EventSubscriber. The EventSubscriber interface includes a very
 * important `add` method that abstracts the needed event to backing store
 * interaction.
 *
 * Storing event data in the backing store must match a table spec for queries.
 * Small overheads exist that help query-time indexing and lookups.
 */
template <class PUB>
class EventSubscriber : public EventSubscriberPlugin {
 protected:
  using SCRef = typename PUB::SCRef;
  using ECRef = typename PUB::ECRef;

 public:
  /**
   * @brief The registry plugin name for the subscriber's publisher.
   *
   * During event factory initialization the subscribers 'peek' at the registry
   * plugin name assigned to publishers. The corresponding publisher name is
   * interpreted as the subscriber's event 'type'.
   */
  const std::string& getType() const override {
    static const std::string type = EventFactory::getType<PUB>();
    return type;
  };

 protected:
  /// Helper function to call the publisher's templated subscription generator.
  SCRef createSubscriptionContext() const {
    return PUB::createSubscriptionContext();
  }

  /**
   * @brief Bind a registered EventSubscriber member function to a Subscription.
   *
   * @param entry A templated EventSubscriber member function.
   * @param sc The subscription context.
   */
  template <class T, typename E>
  void subscribe(Status (T::*entry)(const std::shared_ptr<E>&, const SCRef&),
                 const SCRef& sc) {
    using std::placeholders::_1;
    using std::placeholders::_2;
    using CallbackFunc =
        Status (T::*)(const EventContextRef&, const SubscriptionContextRef&);

    // Down-cast the pointer to the member function.
    auto base_entry = reinterpret_cast<CallbackFunc>(entry);
    // Up-cast the EventSubscriber to the caller.
    auto sub = dynamic_cast<T*>(this);
    if (base_entry != nullptr && sub != nullptr) {
      // Create a callable through the member function using the instance of the
      // EventSubscriber and a single parameter placeholder (the EventContext).
      auto cb = std::bind(base_entry, sub, _1, _2);
      // Add a subscription using the callable and SubscriptionContext.
      Status stat =
          EventFactory::addSubscription(sub->getType(), sub->getName(), sc, cb);
      if (stat.ok()) {
        subscription_count_++;
      }
    }
  }

 public:
  explicit EventSubscriber(bool enabled = true)
      : EventSubscriberPlugin(), disabled(!enabled) {}
  ~EventSubscriber() override = default;

 protected:
  /**
   * @brief Allow subscriber implementations to default disable themselves.
   *
   * A subscriber may induce latency on a system within the callback routines.
   * Before the initialization and set up is performed the EventFactory can
   * choose to exclude a subscriber if it is not explicitly enabled within
   * the config.
   *
   * EventSubscriber%s that should be default-disabled should set this flag
   * in their constructor or worst case before EventSubsciber::init.
   */
  bool disabled{false};

 private:
  friend class EventFactory;

 private:
  FRIEND_TEST(EventsTests, test_event_sub);
  FRIEND_TEST(EventsTests, test_event_sub_subscribe);
  FRIEND_TEST(EventsTests, test_event_sub_context);
  FRIEND_TEST(EventsTests, test_event_toggle_subscribers);
};

} // namespace osquery
