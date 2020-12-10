/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/eventpublisherplugin.h>

namespace osquery {

/**
 * @brief DECLARE_PUBLISHER supplies needed boilerplate code that applies a
 * string-type EventPublisherID to identify the publisher declaration.
 */
#define DECLARE_PUBLISHER(TYPE)                                                \
 public:                                                                       \
  const std::string type() const override final {                              \
    return TYPE;                                                               \
  }

/**
 * @brief Generate OS events of a type (FS, Network, Syscall, ioctl).
 *
 * A 'class' of OS events is abstracted into an EventPublisher responsible for
 * remaining as agile as possible given a known-set of subscriptions.
 *
 * The life cycle of an EventPublisher may include, `setUp`, `configure`, `run`,
 * `tearDown`, and `fire`. `setUp` and `tearDown` happen when osquery starts and
 * stops either as a daemon or interactive shell. `configure` is a pseudo-start
 * called every time a Subscription is added. EventPublisher%s can adjust their
 * scope/agility specific to each added subscription by overriding
 *`addSubscription`, and/or globally in `configure`.
 *
 * Not all EventPublisher%s leverage pure async OS APIs, and most will require a
 * run loop either polling with a timeout on a descriptor or for a change. When
 * osquery initializes the EventFactory will optionally create a thread for each
 * EventPublisher using `run` as the thread's entrypoint. `run` is called in a
 * within-thread loop where returning a FAILED status ends the run loop and
 * shuts down the thread.
 *
 * To opt-out of polling in a thread, consider the following run implementation:
 *
 * @code{.cpp}
 *   Status run() { return Status(1, "Not Implemented"); }
 * @endcode
 *
 * The final life cycle component, `fire` will iterate over the EventPublisher
 * Subscription%s and call `shouldFire` for each, using the EventContext fired.
 * The `shouldFire` method should check the subscription-specific selectors and
 * only call the Subscription%'s callback function if the EventContext
 * (thus event) matches.
 */
template <typename SC, typename EC>
class EventPublisher : public EventPublisherPlugin {
 public:
  /// A nested helper typename for the templated SubscriptionContextRef.
  using SCRef = typename std::shared_ptr<SC>;

  /// A nested helper typename for the templated EventContextRef.
  using ECRef = typename std::shared_ptr<EC>;

 public:
  EventPublisher() = default;
  ~EventPublisher() override = default;

  /// Up-cast a base EventContext reference to the templated ECRef.
  static ECRef getEventContext(const EventContextRef& ec) {
    return std::static_pointer_cast<EC>(ec);
  };

  /// Up-cast a base SubscriptionContext reference to the templated SCRef.
  static SCRef getSubscriptionContext(const SubscriptionContextRef& sc) {
    return std::static_pointer_cast<SC>(sc);
  }

  /// Create a EventContext based on the templated type.
  static ECRef createEventContext() {
    return std::make_shared<EC>();
  }

  /// Create a SubscriptionContext based on the templated type.
  static SCRef createSubscriptionContext() {
    return std::make_shared<SC>();
  }

 protected:
  /**
   * @brief The internal `fire` phase of publishing.
   *
   * This is a template-generated method that up-casts the generic fired
   * event/subscription contexts, and calls the callback if the event should
   * fire given a subscription.
   *
   * @param sub The SubscriptionContext and optional EventCallback.
   * @param ec The event that was fired.
   */
  void fireCallback(const SubscriptionRef& sub,
                    const EventContextRef& ec) const override {
    auto pub_sc = getSubscriptionContext(sub->context);
    auto pub_ec = getEventContext(ec);

    if (shouldFire(pub_sc, pub_ec) && sub->callback != nullptr) {
      sub->callback(pub_ec, pub_sc);
    }
  }

 protected:
  /**
   * @brief The generic `fire` will call `shouldFire` for each Subscription.
   *
   * @param sc A SubscriptionContext with optional specifications for events
   * details.
   * @param ec The event fired with event details.
   *
   * @return should the Subscription%'s EventCallback be called for this event.
   */
  virtual bool shouldFire(const SCRef&, const ECRef&) const {
    return true;
  }

 private:
  FRIEND_TEST(EventsTests, test_event_subscriber_subscribe);
  FRIEND_TEST(EventsTests, test_event_subscriber_context);
  FRIEND_TEST(EventsTests, test_fire_event);
};

} // namespace osquery
