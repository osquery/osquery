/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/plugins/plugin.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/eventer.h>
#include <osquery/events/subscription.h>
#include <osquery/events/types.h>

namespace osquery {

class EventPublisherPlugin : public Plugin,
                             public InterruptibleRunnable,
                             public Eventer {
 public:
  /**
   * @brief A new Subscription was added, potentially change state based on all
   * subscriptions for this EventPublisher.
   *
   * `configure` allows the EventPublisher to optimize on the state of all
   * subscriptions. An example is Linux `inotify` where multiple
   * EventSubscription%s will subscription identical paths, e.g., /etc for
   * config changes. Since Linux `inotify` has a subscription limit, `configure`
   * can dedup paths.
   */
  void configure() override;

  /**
   * @brief Perform handle opening, OS API callback registration.
   *
   * `setUp` is the event framework's EventPublisher constructor equivalent.
   * This is called in the main thread before the publisher's run loop has
   * started, immediately following registration.
   */
  Status setUp() override;

  /**
   * @brief Perform handle closing, resource cleanup.
   *
   * osquery is about to end, the EventPublisher should close handle descriptors
   * unblock resources, and prepare to exit. This will be called from the main
   * thread after the run loop thread has exited.
   *
   * Expect this may be called multiple times, when the event loop stops and
   * optionally by the publisher destructor.
   */
  void tearDown() override;

  /**
   * @brief Implement a "step" of an optional run loop.
   *
   * @return A SUCCESS status will immediately call `run` again. A FAILED status
   * will exit the run loop and the thread.
   */
  virtual Status run();

  /**
   * @brief Allow the EventFactory to interrupt the run loop.
   *
   * Assume the main thread may ask the run loop to stop at anytime.
   * Before end is called the publisher's `isEnding` is set and the EventFactory
   * run loop manager will exit the stepping loop and fall through to a call
   * to tearDown followed by a removal of the publisher.
   */
  void stop() override;

  /// This is a plugin type and must implement a call method.
  Status call(const PluginRequest& /*request*/,
              PluginResponse& /*response*/) override;

  /**
   * @brief A new EventSubscriber is subscribing events of this publisher type.
   *
   * @param subscription The Subscription context information and optional
   * EventCallback.
   *
   * @return If the Subscription is not appropriate (mismatched type) fail.
   */
  virtual Status addSubscription(const SubscriptionRef& subscription);

  /// Remove all subscriptions from a named subscriber.
  virtual void removeSubscriptions(const std::string& subscriber);

  /// Overriding the EventPublisher constructor is not recommended.
  EventPublisherPlugin() = default;

  /// Destructor
  ~EventPublisherPlugin() override = default;

  /// Return a string identifier associated with this EventPublisher.
  virtual const std::string type() const;

  /// Number of Subscription%s watching this EventPublisher.
  size_t numSubscriptions();

  /**
   * @brief The number of events fired by this EventPublisher.
   *
   * @return The number of events.
   */
  EventContextID numEvents() const;

  /// Check if the EventFactory is ending all publisher threads.
  bool isEnding() const;

  /// Set the ending status for this publisher.
  void isEnding(bool ending);

  /// Check if the publisher's run loop has started.
  bool hasStarted() const;

  /// Set the run or started status for this publisher.
  void hasStarted(bool started);

  /// Get the number of publisher restarts.
  size_t restartCount() const;

  explicit EventPublisherPlugin(EventPublisherPlugin const&) = delete;
  EventPublisherPlugin& operator=(EventPublisherPlugin const&) = delete;

 protected:
  /**
   * @brief The generic check loop to call SubscriptionContext callback methods.
   *
   * It is NOT recommended to override `fire`. The simple logic of enumerating
   * the Subscription%s and using `shouldFire` is more appropriate.
   *
   * @param ec The EventContext created and fired by the EventPublisher.
   * @param time The most accurate time associated with the event.
   */
  void fire(const EventContextRef& ec, EventTime time = 0);

  /// The internal fire method used by the typed EventPublisher.
  virtual void fireCallback(const SubscriptionRef& sub,
                            const EventContextRef& ec) const = 0;

  /// Return the current time (included to assist testing).
  virtual uint64_t getTime() const;

  /// A lock for subscription manipulation.
  mutable Mutex subscription_lock_;

  /// The EventPublisher will keep track of Subscription%s that contain callins.
  SubscriptionVector subscriptions_;

  /// An Event ID is assigned by the EventPublisher within the EventContext.
  /// This is not used to store event date in the backing store.
  std::atomic<EventContextID> next_ec_id_{0};

 private:
  /// Set ending to True to cause event type run loops to finish.
  std::atomic<bool> ending_{false};

  /// Set to indicate whether the event run loop ever started.
  std::atomic<bool> started_{false};

  /// A helper count of event publisher runloop iterations.
  std::atomic<size_t> restart_count_{0};

  // clang-format off
  [[deprecated("Do not check for interrupted, instead use isEnding.")]]
  // clang-format on
  virtual bool
  interrupted() override;

  /// Enable event factory "callins" through static publisher callbacks.
  friend class EventFactory;

  FRIEND_TEST(EventsTests, test_event_publisher);
  FRIEND_TEST(EventsTests, test_fire_event);
};
} // namespace osquery
