/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <typeindex>

namespace osquery {
namespace ev2 {

/**
 * @brief Interface between a ev2::Publisher and a subscriber
 *
 * @details A ev2::Subscription is the interface between a ev2::Publisher and a
 * subscriber interested in consuming events. It allows the subscriber to
 * register with the ev2::Publisher and define the subscription parameters
 * (e.g. the type of events it is interested on, advanced filters, etc) and
 * mediates the transfer of events from the ev2::Publisher to the subscriber
 * while allowing to decouple the two instances which only need to share a
 * pointer to the ev2::Subscription usually using an ev2::EventManager.
 *
 * The ev2::Subscription is meant to be specialized by each ev2::Publisher to
 * suit its needs, and therefore the basic interface is intentionally simple
 * providing only a basic mechanism for determining the publisher the
 * subscriber is interested on (which will be used by the ev2::EventManager to
 * route request to registered ev2::Publisher instances) and a mechanism to
 * query about the availability of new events. It says nothing about the way
 * events are passed around, buffered or otherwise managed and is up to the
 * ev2::Publisher to define those interfaces. Some basic interfaces accepting
 * parameterized event types are provided like the ev2::BufferedSubscription
 * which can be further specialized by the ev2::Publisher.
 */
class Subscription {
 public:
  /**
   * @brief Subscription constructor.
   *
   * @param subscriber Subscriber name used for logging.
   *
   * @param pub_type Type of publisher to register with, used by an
   * ev2::EventManager to route ev2::EventManager::bind() calls.
   */
  explicit Subscription(std::string subscriber, std::type_index pub_type);
  virtual ~Subscription() = default;

  /**
   * @brief Retrieve the subscriber name.
   *
   * @returns A const reference to the subscriber name with the lifetime of the
   * ev2::Subscription object.
   */
  const std::string& subscriber() const;
  /**
   * @brief Retrieve the publisher type.
   *
   * @returns A const reference to std::type_index of the subscriber with the
   * lifetime of the ev2::Subscription.
   */
  const std::type_index& pubType() const;

  /**
   * @brief Query number of available events.
   *
   * @details Allows a subscriber to query the number of pending events handled
   * by this subscription. The semantics about how events are managed are up to
   * the specifc ev2::Subscription specialization.
   */
  virtual std::size_t avail() const = 0;

  /**
   * @brief Wait for events to be available.
   *
   * @details Allows the subscriber to block until events are available,
   * optionally providing a batch size and a timeout. The call will return as
   * soon as batch events is available, timeout is reached, or abort() is called
   * whichever comes first.
   *
   * @params batch The number of events to wait for before returning. The call
   * will return as soon as batch number of events are available, by default 1,
   * independently of the timeout set.
   *
   * @params timeout The maximum time to wait for events. The call will return
   * once as soon as timeout is reached independently of the number of events
   * available. A timeout value of zero means no timeout.
   */
  virtual std::size_t wait(std::size_t batch = 1,
                           std::chrono::milliseconds timeout =
                               std::chrono::milliseconds::zero()) = 0;

  /**
   * @brief Abort all pending wait() calls.
   *
   * @details Makes all currently blocking wait() calls return independently of
   * the number of available events.
   */
  virtual void abort() = 0;

 private:
  const std::string subscriber_;
  const std::type_index pub_type_;
};

} // namespace ev2
} // namespace osquery
