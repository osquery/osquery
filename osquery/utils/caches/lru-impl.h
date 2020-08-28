/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

namespace osquery {
namespace caches {

template <typename KeyType, typename ValueType>
ValueType const* LRU<KeyType, ValueType>::insert(const KeyType& key,
                                                 ValueType value) {
  auto map_iter = map_.find(key);
  if (map_iter == map_.end()) {
    if (size() >= capacity_) {
      evict();
    }
    queue_.push_front(key);
    auto const inserted_element_iter =
        map_.emplace(key, ValueAndIterType{std::move(value), queue_.begin()})
            .first;
    return &inserted_element_iter->second.value;
  } else {
    map_iter->second.value = std::move(value);
    queue_.erase(map_iter->second.iter);
    queue_.push_front(key);
    map_iter->second.iter = queue_.begin();
  }
  return &map_iter->second.value;
}

template <typename KeyType, typename ValueType>
ValueType const* LRU<KeyType, ValueType>::get(const KeyType& key) {
  auto map_iter = map_.find(key);
  if (map_iter == map_.end()) {
    return nullptr;
  }
  auto queue_iter = map_iter->second.iter;
  if (queue_iter != queue_.begin()) {
    queue_.erase(queue_iter);
    queue_.push_front(key);
    map_iter->second.iter = queue_.begin();
  }
  return &map_iter->second.value;
}

} // namespace caches
} // namespace osquery
