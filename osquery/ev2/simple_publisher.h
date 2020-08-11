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
#include <string>
#include <vector>

namespace osquery {
namespace ev2 {

/**
 * @brief Basic publisher implementation.
 *
 * @details This is a basic publisher implementation which supports basic
 * subscription registering and event forwarding. The publisher will simply
 * forward events to all registered subscriptions. It will also keep the event
 * id counter for producers to rely on.
 */
template <typename SubscriptionT>
class SimplePublisher : public Publisher {
 public:
  /**
   * @brief SimplePublisher constructor.
   *
   * @param name Publisher name to be passed to ev2::Publisher::Publisher().
   */
  SimplePublisher(const std::string name) : Publisher(std::move(name)) {}
  virtual ~SimplePublisher() = default;

  /**
   * @brief Register a new ev2::Subscription to receive events from this
   * publisher.
   *
   * @details Register a new subscription object of type SubscriptionT to start
   * receiving events from this publisher. As soon as the subscription is
   * registered, the publisher will start forwarding events. No historical
   * events will be forward.
   *
   * @param base_sub A shared pointer to a ev2::Subscription object. This
   * pointer should point to an object of type SubscriptionT.
   */
  ExpectedSuccess<Publisher::Error> subscribe(
      std::shared_ptr<Subscription> base_sub) final override {
    auto sub = std::dynamic_pointer_cast<SubscriptionT>(base_sub);
    if (!sub) {
      return createError(Publisher::Error::InvalidSubscription)
             << "SimplePublisher::subscribe() called with invalid subscription "
                "type.";
    }

    auto ret = reconfigure(sub);

    if (!ret) {
      subs_.push_back(sub);
    }

    return ret;
  }

 protected:
  /**
   * @brief Reconfigure the publisher to start forwarding events to a new
   * ev2::Subscription.
   *
   * @details If necessary, specializations of ev2::SimplePublisher should
   * override reconfigure() to setup any internal state necessary to start
   * forwarding events to a new ev2::Subscription.
   */
  virtual ExpectedSuccess<Publisher::Error> reconfigure(
      const std::shared_ptr<SubscriptionT>& sub) {
    return Success();
  }

 protected:
  std::vector<std::shared_ptr<SubscriptionT>> subs_;
};

} // namespace ev2
} // namespace osquery
