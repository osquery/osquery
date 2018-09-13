/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/map.h"
#include "osquery/events/linux/ebpf/system.h"

#include <boost/io/detail/quoted_manip.hpp>

#include <cerrno>
#include <cstring>

namespace osquery {
namespace ebpf {

namespace impl {

Expected<int, MapError> mapCreate(enum bpf_map_type map_type,
                                  std::size_t key_size,
                                  std::size_t value_size,
                                  std::size_t max_entries) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(union bpf_attr));
  attr.map_type = map_type;
  attr.key_size = static_cast<std::uint32_t>(key_size);
  attr.value_size = static_cast<std::uint32_t>(value_size);
  attr.max_entries = static_cast<std::uint32_t>(max_entries);

  int const ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  if (ret < 0) {
    return createError(MapError::SystemError, "Creating eBPF map failed: ")
           << boost::io::quoted(strerror(errno));
  }
  return ret;
}

ExpectedSuccess<MapError> mapUpdateElement(const int fd,
                                           void const* key,
                                           void const* value,
                                           unsigned long long flags) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(union bpf_attr));
  attr.map_fd = fd;
  attr.key = reinterpret_cast<std::uint64_t>(key);
  attr.value = reinterpret_cast<std::uint64_t>(value);
  attr.flags = flags;

  int const ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  if (ret < 0) {
    return createError(MapError::SystemError,
                       "Updating value in eBPF map failed: ")
           << boost::io::quoted(strerror(errno));
  }
  return Success{};
}

ExpectedSuccess<MapError> mapLookupElement(const int fd,
                                           void const* key,
                                           void* value) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(union bpf_attr));
  attr.map_fd = fd;
  attr.key = reinterpret_cast<std::uint64_t>(key);
  attr.value = reinterpret_cast<std::uint64_t>(value);

  int const ret = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
  if (ret < 0) {
    auto err_code = MapError::SystemError;
    if (errno == ENOENT) {
      err_code = MapError::NoSuchKey;
    }
    return createError(err_code, "Look up in eBPF map failed: ")
           << boost::io::quoted(strerror(errno));
  }
  return Success{};
}

ExpectedSuccess<MapError> mapDeleteElement(const int fd, void const* key) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(union bpf_attr));
  attr.map_fd = fd;
  attr.key = reinterpret_cast<std::uint64_t>(key);

  int const ret = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
  if (ret < 0) {
    return createError(MapError::SystemError,
                       "Deleting element from eBPF map failed: ")
           << boost::io::quoted(strerror(errno));
  }
  return Success{};
}

} // namespace impl

} // namespace ebpf
} // namespace osquery
