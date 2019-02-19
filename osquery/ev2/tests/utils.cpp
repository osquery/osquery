/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/ev2/tests/utils.h>

namespace osquery {
namespace ev2 {

TestEvent::TestEvent(Id _id, Time _time) : id(_id), time(_time) {}

bool TestEvent::operator==(const TestEvent& rhs) const {
  return (id == rhs.id) && (time == rhs.time);
}

bool TestEvent::operator!=(const TestEvent& rhs) const {
  return !(*this == rhs);
}

NullPublisher::NullPublisher(const std::string& name) : Publisher(name) {}

ExpectedSuccess<Publisher::Error> NullPublisher::subscribe(
    std::shared_ptr<Subscription> subscription) {
  return Success();
}

NullSubscription::NullSubscription(const std::string& subscriber)
    : Subscription(subscriber, typeid(NullPublisher)) {}

std::size_t NullSubscription::avail() const {
  return 0;
}

std::size_t NullSubscription::wait(std::size_t batch,
                                   std::chrono::milliseconds timeout) {
  return batch;
}

void NullSubscription::abort() {}

} // namespace ev2
} // namespace osquery
