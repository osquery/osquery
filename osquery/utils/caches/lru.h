/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <list>
#include <unordered_map>

namespace osquery {
namespace caches {

/**
 * Yet another implementation of well known LRU cache.
 *
 * This cache discards the least recently used items (items at the end of the
 * queue) first. Insert and every access to the element push it up to the
 * beginning of the queue.
 */
template <typename KeyType_, typename ValueType_>
class LRU {
 public:
  using KeyType = KeyType_;
  using ValueType = ValueType_;
  using QueueType = std::list<KeyType>;
  struct ValueAndIterType {
    ValueType value;
    typename QueueType::iterator iter;
  };
  using MapType = std::unordered_map<KeyType, ValueAndIterType>;

  /**
   * @brief Create LRU cache with a certain capacity.
   *
   * @param capacity of the cache
   */
  explicit LRU(std::size_t capacity) : capacity_(capacity) {}

  /**
   * @brief Insert new key and value to the cache.
   *
   * @details Key and value are taken by const reference, that means they will
   * be copied to cache. If value with the same kay is exists in the cache it
   * will be replaced with new one.
   *
   * @param KeyType key of the inserting element
   * @param ValueType the element to store in cache
   *
   * @returns constant pointer to cached element.
   */
  ValueType const* insert(const KeyType& key, ValueType value);

  /**
   * @brief Get value from cache by key if it is in the cache.
   *
   * @details The successful access will push the element up to the beginning of
   * the queue.
   *
   * @param KeyType key of the element to search for
   *
   * @returns constant pointer to cached element, if there is no such key
   * nullptr will be returned.
   */
  ValueType const* get(const KeyType& key);

  /**
   * @returns the number of cached elements.
   */
  std::size_t size() const noexcept {
    return map_.size();
  }

  /**
   * @returns the capacity of the cache
   */
  std::size_t capacity() const noexcept {
    return capacity_;
  }

  /**
   * @brief Test if certain key exists in the cache. Method doesn't change the
   * place in the queue.
   *
   * @param KeyType key of the element to search for.
   *
   * @returns true if certain key exists in the cache.
   */
  bool has(const KeyType& key) const {
    return map_.find(key) != map_.end();
  }

 private:
  void evict() {
    map_.erase(queue_.back());
    queue_.pop_back();
  }

 private:
  MapType map_;
  QueueType queue_;
  std::size_t const capacity_;
};

} // namespace caches
} // namespace osquery

#include <osquery/utils/caches/lru-impl.h>
