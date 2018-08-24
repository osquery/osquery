/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <osquery/ev2/manager.h>

namespace osquery {
namespace ev2 {

void EventManager::bind(std::shared_ptr<Subscription> sub)
{
    auto it = publishers_.find(sub->pub_type());
    if (it != publishers_.end()) {
      it->second->subscribe(std::move(sub));
    }
}

void EventManager::register_publisher(std::shared_ptr<Publisher> pub)
{
  auto& r = *pub.get();
  publishers_[typeid(r)] = std::move(pub);
}

} // namespace ev2
} // namespace osquery
