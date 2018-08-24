/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <osquery/ev2/subscription.h>

namespace osquery {
namespace ev2 {

Subscription::Subscription(
    const std::string& subscriber,
    const std::type_index& pub_type)
  : subscriber_(subscriber)
  , pub_type_(pub_type)
{
}

const std::string& Subscription::subscriber() const
{
  return subscriber_;
}

const std::type_index& Subscription::pub_type() const
{
  return pub_type_;
}

} // namespace ev2
} // namespace osquery
