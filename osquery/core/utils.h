/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <ctime>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>

#include <osquery/expected.h>

namespace osquery {

/// Returns the ASCII version of the timeptr as a C++ string
std::string platformAsctime(const struct tm* timeptr);

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

#ifdef OSQUERY_POSIX
/// Safer way to do realpath
const std::string canonicalize_file_name(const char* name);
#endif

enum class GetError {
  KeyError,
};

namespace impl {

template <class T>
struct IsMap : std::false_type {};

template<class Key, class Value>
struct IsMap<std::map<Key,Value>> : std::true_type {};

template<class Key, class Value>
struct IsMap<std::unordered_map<Key,Value>> : std::true_type {};

}  // namespace impl

template <
  typename MapType
  , typename KeyType = typename MapType::key_type
  , typename ValueType = typename MapType::mapped_type
>
inline typename std::enable_if<
    impl::IsMap<MapType>::value,
    Expected< std::reference_wrapper<const ValueType>, GetError >
>::type
tryGet(const MapType& from, const KeyType& key) {
  auto it = from.find(key);
  if (it == from.end()) {
    return createError(GetError::KeyError, "key error");
  }
  return std::cref(it->second);
}

template <
  typename MapType
  , typename KeyType = typename MapType::key_type
  , typename ValueType = typename MapType::mapped_type
>
inline typename std::enable_if<
    impl::IsMap<MapType>::value,
    Expected<ValueType, GetError >
>::type
tryGetCopy(const MapType& from, const KeyType& key) {
  auto it = from.find(key);
  if (it == from.end()) {
    return createError(GetError::KeyError, "key error");
  }
  return it->second;
}

template <
  typename MapType
  , typename KeyType = typename MapType::key_type
  , typename ValueType = typename MapType::mapped_type
>
inline typename std::enable_if<
    impl::IsMap<MapType>::value,
    Expected<ValueType, GetError>
>::type
tryTake(MapType& from, const KeyType& key) {
  auto it = from.find(key);
  if (it == from.end()) {
    return createError(GetError::KeyError, "key error");
  }
  auto item = std::move(it->second);
  from.erase(it);
  return item;
}

template <
  typename MapType
  , typename KeyType = typename MapType::key_type
  , typename ValueType = typename MapType::mapped_type
>
inline typename const std::enable_if<
    impl::IsMap<MapType>::value,
    ValueType
>::type&
getOr(const MapType& from, const KeyType& key, const ValueType& defaultValue) {
  auto it = from.find(key);
  if (it == from.end()) {
    return defaultValue;
  }
  return it->second;
}

}
