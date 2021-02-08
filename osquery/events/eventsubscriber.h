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
  template <typename T>
  void subscribe(Status (T::*entry)(const ECRef&, const SCRef&),
                 const SCRef& sc) {
    // Down-cast the EventSubscriber to the caller.
    auto sub = dynamic_cast<T*>(this);
    if (sub != nullptr) {
      /* Create a lambda to call the "sub" event subscriber callback passed as
         "entry", properly handling the downcast of the callback arguments. The
         lambda is supposed to be saved into a std::function that hides the
         subscriber type, and uses base classes for the callback arguments, so
         that it can be saved in a generic container.*/
      auto cb = [sub, entry](const EventContextRef& ec,
                             const SubscriptionContextRef& sc) -> Status {
        return std::invoke(
            entry,
            *sub,
            std::dynamic_pointer_cast<typename ECRef::element_type>(ec),
            std::dynamic_pointer_cast<typename SCRef::element_type>(sc));
      };

      // Add a subscription using the callable and
      // SubscriptionContext.
      Status stat =
          EventFactory::addSubscription(sub->getType(), sub->getName(), sc, cb);
      if (stat.ok()) {
        subscription_count_++;
      }
    }
  }

 public:
  explicit EventSubscriber(bool enabled = true)
      : EventSubscriberPlugin(enabled) {}
};

} // namespace osquery
