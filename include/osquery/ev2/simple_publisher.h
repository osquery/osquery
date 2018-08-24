/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/ev2/event.h>
#include <osquery/ev2/publisher.h>
#include <osquery/ev2/subscription.h>

namespace osquery {
namespace ev2 {

template <typename SubscriptionT>
class SimplePublisher : public Publisher {
 public:
  SimplePublisher(const std::string& name)
    : Publisher(name)
    , next_id_(0)
  { }
  virtual ~SimplePublisher() = default;

  void subscribe(std::shared_ptr<Subscription> base_sub) final override
  {
    auto sub = std::dynamic_pointer_cast<SubscriptionT>(base_sub);
    if (!sub) {
      return /* error */;
    }

    if (reconfigure(sub)) {
      subs_.push_back(sub);
    } else {
      return /* error */;
    }

    return /* success */;
  }

 protected:
  virtual bool reconfigure(const std::shared_ptr<SubscriptionT>& sub)
  {
    return true;
  }

 protected:
  EventId next_id_;
  std::vector<std::shared_ptr<SubscriptionT> > subs_;
};

} // namespace ev2
} // namespace osquery
