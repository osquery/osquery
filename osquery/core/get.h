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

#include <map>
#include <unordered_map>

#include <osquery/expected.h>

namespace osquery {

/**
 * Helper functions to look up in key-value tables.
 *
 * There are several reasons for using this code:
 *   1. To reduce amount of code and increase the readability of it.
 *      Instead of verbose piece of code such as:
 *      @code{.cpp}
 *        auto takenValue = ValueType{};
 *        auto const it = table.find("key");
 *        if (it != table.end()) {
 *          takenValue = it->second;
 *        }
 *      @endcode
 *      Have more short and simple:
 *      @code{.cpp}
 *        auto const it = tryTakeCopy(table, "key").takeOr(ValueType{});
 *      @endcode
 *
 *   2. To avoid nonoptimal code with two exactly the same lookups, e.g.:
 *      @code{.cpp}
 *        auto takenValue = table.count(key) ? table.at(key) : ValueType{};
 *      @endcode
 *
 *   3. To reduce the possibility of dangerous misstypes such as:
 *      @code{.cpp}
 *        auto takenValue = table.count("key") ? table.at("Key") : ValueType{};
 *      @endcode
 */

enum class GetError {
  KeyError,
};

namespace impl {

template <typename T>
struct IsMap : std::false_type {};

template <typename... TemplateArgs>
struct IsMap<std::map<TemplateArgs...>> : std::true_type {};

template <typename... TemplateArgs>
struct IsMap<std::unordered_map<TemplateArgs...>> : std::true_type {};

} // namespace impl

/**
 * @brief Take out object from the table by key
 *
 * @param table to look up (std::map or std::unordered_map)
 * @param key to look up by in the table
 *
 * @return Expected object with value if such key exists in the table,
 * otherwise Error of type GetError
 */
template <typename MapType,
          typename KeyType = typename MapType::key_type,
          typename ValueType = typename MapType::mapped_type>
inline typename std::enable_if<impl::IsMap<MapType>::value,
                               Expected<ValueType, GetError>>::type
tryTake(MapType& table, const KeyType& key) {
  auto it = table.find(key);
  if (it == table.end()) {
    return createError(GetError::KeyError, "no such key in the table");
  }
  auto item = std::move(it->second);
  table.erase(it);
  return item;
}

/**
 * @brief Take object copy from the table by key
 *
 * @param table to look up (std::map or std::unordered_map)
 * @param key to look up by in the table
 *
 * @return Expected object with value if such key exists in the table,
 * otherwise Error of type GetError
 */
template <typename MapType,
          typename KeyType = typename MapType::key_type,
          typename ValueType = typename MapType::mapped_type>
inline typename std::enable_if<impl::IsMap<MapType>::value,
                               Expected<ValueType, GetError>>::type
tryTakeCopy(MapType const& from, KeyType const& key) {
  auto const it = from.find(key);
  if (it == from.end()) {
    return createError(GetError::KeyError, "no such key in the table");
  }
  return it->second;
}

template <typename T>
class Eprst;

/**
 * @brief Get constant reference to the object in given table by key
 * or constant reference to default value.
 *
 * @param table to look up (std::map or std::unordered_map)
 * @param key to look up by in the table
 *
 * @return constant reference to the object in given table by key, if such key
 * exists in the table, otherwise constant reference to given default value
 */
template <typename MapType,
          typename KeyType = typename MapType::key_type,
          typename DefaultValueType = typename MapType::mapped_type>
inline typename std::enable_if<impl::IsMap<MapType>::value,
                               typename MapType::mapped_type const&>::type
getOr(MapType const& from,
      KeyType const& key,
      DefaultValueType&& defaultValue) {
  static_assert(std::is_lvalue_reference<DefaultValueType>::value,
                "A default value is suppose to be reference to a mapped_type");
  auto const it = from.find(key);
  if (it == from.end()) {
    return defaultValue;
  }
  return it->second;
}

} // namespace osquery
