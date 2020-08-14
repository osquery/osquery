/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/ev2/publisher.h>
#include <osquery/ev2/subscription.h>
#include <osquery/utils/expected/expected.h>

#include <memory>
#include <mutex>
#include <typeindex>
#include <unordered_map>
#include <utility>

namespace osquery {
namespace ev2 {

/**
 * @brief ev2::Publisher registry.
 *
 * @details The ev2::EventManager provides a mechanism for to register a
 * ev2::Subscription with the correspondent ev2::Publisher without the need for
 * consumer and provider to know each other, useful for when producers and
 * consumers appear dynamically on the system.
 *
 * Note that an ev2::EventManager is not required for a functioning ev2 based
 * system as consumers can register subscriptions with publishers by calling
 * ev2::Publisher::subscribe() directly.
 */
class EventManager {
 public:
  enum class Error {
    UnknownPublisher,
    PublisherError,
  };

  EventManager() = default;

  EventManager(const EventManager&) = delete;
  EventManager& operator=(const EventManager&) = delete;

  /**
   * @brief Register a ev2::Subscription with existing ev2::Publisher.
   *
   * @details When calling bind() the ev2::EventManager will look for a
   * registered ev2::Publisher of the type specified by calling
   * ev2::Subscription::pubType() on the provided ev2::Subscription instance
   * and, if an appropriate ev2::Publisher is found, register the
   * ev2::Subscription with it by calling ev::Publisher::subscribe(). If no
   * ev2::Publisher is found no action will be taken and the ev2::Subscription
   * instance can be re-used.
   *
   * @params sub Shared pointer to the ev2::Subscription instance.
   *
   * @returns True if the subscription was properly subscribed, and False
   * otherwise.
   */
  ExpectedSuccess<Error> bind(std::shared_ptr<Subscription> sub);

  /**
   * @brief Register a new ev2::Publisher.
   *
   * @details If a publisher of the same type is already registered it will be
   * replaced.
   *
   * @params pub Shared pointer to the ev2::Publisher instance.
   */
  void registerPublisher(std::shared_ptr<Publisher> pub);

 private:
  std::unordered_map<std::type_index, std::shared_ptr<Publisher>> publishers_;

  mutable std::mutex mutex_;
};

} // namespace ev2
} // namespace osquery
