/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstring>
#include <memory>
#include <string>
#include <type_traits>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {

inline std::string stringFromIOKitProperty(CFTypeRef value) {
  if (value == nullptr) {
    return {};
  }

  const auto type_id = CFGetTypeID(value);
  if (type_id == CFStringGetTypeID()) {
    return stringFromCFString(static_cast<CFStringRef>(value));
  }
  if (type_id == CFDataGetTypeID()) {
    auto data = static_cast<CFDataRef>(value);
    const CFIndex length = CFDataGetLength(data);
    const auto* bytes = CFDataGetBytePtr(data);
    if (length < 1 || bytes == nullptr) {
      return {};
    }
    const auto* begin = reinterpret_cast<const char*>(bytes);
    return std::string(begin, strnlen(begin, static_cast<std::size_t>(length)));
  }
  return {};
}

template <typename Type>
struct ObjectDeleter final {
  static_assert(std::is_same_v<io_object_t, Type>,
                "Type is not compatible with an io_object_t");

  using pointer = Type;

  void operator()(pointer p) {
    if (p == 0) {
      return;
    }

    IOObjectRelease(p);
  }
};

template <typename Type>
struct TypeDeleter final {
  using pointer = Type;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

using UniqueIoRegistryEntry =
    std::unique_ptr<io_registry_entry_t, ObjectDeleter<io_registry_entry_t>>;
using UniqueIoIterator =
    std::unique_ptr<io_iterator_t, ObjectDeleter<io_iterator_t>>;
using UniqueIoService =
    std::unique_ptr<io_service_t, ObjectDeleter<io_service_t>>;

using UniqueCFStringRef =
    std::unique_ptr<CFStringRef, TypeDeleter<CFStringRef>>;
using UniqueCFTypeRef = std::unique_ptr<CFTypeRef, TypeDeleter<CFTypeRef>>;
using UniqueCFMutableDictionaryRef =
    std::unique_ptr<CFMutableDictionaryRef,
                    TypeDeleter<CFMutableDictionaryRef>>;
} // namespace osquery
