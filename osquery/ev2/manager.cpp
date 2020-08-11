/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/ev2/manager.h>
#include <osquery/utils/expected/expected.h>

#include <mutex>

namespace osquery {
namespace ev2 {

ExpectedSuccess<EventManager::Error> EventManager::bind(
    std::shared_ptr<Subscription> sub) {
  std::unique_lock<std::mutex> lock(mutex_);

  auto it = publishers_.find(sub->pubType());
  if (it != publishers_.end()) {
    auto ret = it->second->subscribe(std::move(sub));
    if (ret.isError()) {
      return createError(Error::PublisherError, ret.takeError())
             << "Calling subscribe() on publisher '" << it->second->name()
             << "' for subscription from request from '" << sub->subscriber()
             << "' returned an error.";
    }
  } else {
    return createError(Error::UnknownPublisher)
           << "No registered publisher for bind request from '"
           << sub->subscriber() << "'";
  }

  return Success();
}

void EventManager::registerPublisher(std::shared_ptr<Publisher> pub) {
  std::unique_lock<std::mutex> lock(mutex_);

  auto& r = *pub.get();
  publishers_[typeid(r)] = std::move(pub);
}

} // namespace ev2
} // namespace osquery
