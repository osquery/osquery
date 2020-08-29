/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/expected/expected.h>

#include <linux/bpf.h>

namespace osquery {
namespace ebpf {

enum class MapError {
  Unknown = 1,
  NoSuchKey = 2,
};

namespace impl {
/**
 * Do not use implementation functions directly, use Map class to create and
 * manage eBPF map
 */
Expected<int, MapError> mapCreate(enum bpf_map_type map_type,
                                  std::size_t key_size,
                                  std::size_t value_size,
                                  std::size_t max_entries);
ExpectedSuccess<MapError> mapUpdateElement(int fd,
                                           void const* key,
                                           void const* value,
                                           unsigned long long flags);
ExpectedSuccess<MapError> mapLookupElement(int fd,
                                           void const* key,
                                           void* value);
ExpectedSuccess<MapError> mapDeleteElement(int fd, void const* key);

} // namespace impl

/**
 * Proxy object for the eBPF map structure in kernel.
 */

template <typename KeyType, typename ValueType, enum bpf_map_type map_type>
class Map final {
 private:
  static_assert(
      std::is_pod<KeyType>::value && std::is_pod<ValueType>::value,
      "Both key type and value type must be a plain old data type (POD)");

  /**
   * The only constructor of Map is private for purpose. Use createMap function
   * instead. Map should not be created in case of creating eBPF map failure.
   */
  explicit Map(int fd, std::size_t size) : fd_(fd), size_(size) {}

 public:
  ~Map() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  Map(Map const&) = delete;

  Map(Map && from) : fd_(from.fd_), size_(from.size_) {
    from.fd_ = -1;
  }

  Map& operator=(Map const&) = delete;

  Map& operator=(Map&& from) {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
    std::swap(fd_, from.fd_);
    std::swap(size_, from.size_);

    return *this;
  }

  Expected<ValueType, MapError> lookupElement(KeyType const& key) const {
    auto value = ValueType{};
    auto exp = impl::mapLookupElement(
        fd_, static_cast<void const*>(&key), static_cast<void*>(&value));
    if (exp.isError()) {
      return exp.takeError();
    }
    return value;
  }

  ExpectedSuccess<MapError> updateElement(KeyType const& key,
                                          ValueType const& value,
                                          unsigned long long flags = BPF_ANY) {
    return impl::mapUpdateElement(fd_,
                                  static_cast<void const*>(&key),
                                  static_cast<void const*>(&value),
                                  flags);
  }

  ExpectedSuccess<MapError> deleteElement(KeyType const& key) {
    return impl::mapDeleteElement(fd_, static_cast<void const*>(&key));
  }

  std::size_t size() const {
    return size_;
  }

  int fd() const {
    return fd_;
  }

  template <typename KType, typename VType, enum bpf_map_type type>
  friend Expected<Map<KType, VType, type>, MapError> createMap(
      std::size_t size);

 private:
  int fd_ = -1;
  std::size_t size_;
};

template <typename KeyType, typename ValueType, enum bpf_map_type map_type>
static Expected<Map<KeyType, ValueType, map_type>, MapError> createMap(
    std::size_t size) {
  auto exp =
      impl::mapCreate(map_type, sizeof(KeyType), sizeof(ValueType), size);
  if (exp.isError()) {
    return exp.takeError();
  }
  return Map<KeyType, ValueType, map_type>(exp.take(), size);
}

} // namespace ebpf
} // namespace osquery
