/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/subscription.h>

namespace osquery {

Subscription::Subscription(std::string name)
    : subscriber_name(std::move(name)){};

SubscriptionRef Subscription::create(const std::string& name) {
  return std::make_shared<Subscription>(name);
}

SubscriptionRef Subscription::create(const std::string& name,
                                     const SubscriptionContextRef& mc,
                                     EventCallback ec) {
  auto subscription = std::make_shared<Subscription>(name);
  subscription->context = mc;
  subscription->callback = std::move(ec);
  return subscription;
}

} // namespace osquery
