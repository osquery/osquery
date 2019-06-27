/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/ev2/subscription.h>

namespace osquery {
namespace ev2 {

Subscription::Subscription(std::string subscriber, std::type_index pub_type)
    : subscriber_(std::move(subscriber)), pub_type_(std::move(pub_type)) {}

const std::string& Subscription::subscriber() const {
  return subscriber_;
}

const std::type_index& Subscription::pubType() const {
  return pub_type_;
}

} // namespace ev2
} // namespace osquery
