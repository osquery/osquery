/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <unordered_map>

#include <osquery/utils/expected/expected.h>

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
 *        auto const takenValue = tryTakeCopy(table, "key").takeOr(ValueType{});
 *      @endcode
 *
 *   2. To avoid nonoptimal code with two exactly the same lookups, e.g.:
 *      @code{.cpp}
 *        auto takenValue = table.count(key) ? table.at(key) : ValueType{};
 *      @endcode
 *
 *   3. To reduce the possibility of dangerous misstypes such as:
 *      @code{.cpp}
 *        auto takenValue = table.count("key") ? table.at("KeY") : ValueType{};
 *      @endcode
 */

enum class MapTakeError {
  NoSuchKey = 1,
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
 * otherwise Error of type MapTakeError
 */
template <typename MapType,
          typename KeyType = typename MapType::key_type,
          typename ValueType = typename MapType::mapped_type>
inline typename std::enable_if<impl::IsMap<MapType>::value,
                               Expected<ValueType, MapTakeError>>::type
tryTake(MapType& table, const KeyType& key) {
  auto it = table.find(key);
  if (it == table.end()) {
    return createError(MapTakeError::NoSuchKey) << "no such key in the table";
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
 * otherwise Error of type MapTakeError
 */
template <typename MapType,
          typename KeyType = typename MapType::key_type,
          typename ValueType = typename MapType::mapped_type>
inline typename std::enable_if<impl::IsMap<MapType>::value,
                               Expected<ValueType, MapTakeError>>::type
tryTakeCopy(MapType const& from, KeyType const& key) {
  auto const it = from.find(key);
  if (it == from.end()) {
    return createError(MapTakeError::NoSuchKey) << "no such key in the table";
  }
  return it->second;
}

} // namespace osquery
