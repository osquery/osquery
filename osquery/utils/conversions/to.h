/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/core/demangle.hpp>
#include <type_traits>

namespace osquery {
/**
 * Non failing conversion functions
 */

/**
 * Conversion either scoped or unscoped enum value to std::string
 * of human readable representation.
 *
 * enum class En {
 *  First = 1,
 * };
 * to<std::string>(En::First) -> "En::First[1]"
 */
template <typename ToType, typename FromType>
inline typename std::enable_if<std::is_enum<FromType>::value &&
                                   std::is_same<ToType, std::string>::value,
                               ToType>::type
to(FromType from) noexcept {
  auto str = ToType{boost::core::demangle(typeid(from).name())};
  str.append("[");
  str.append(std::to_string(
      static_cast<typename std::underlying_type<FromType>::type>(from)));
  str.append("]");
  return str;
}

} // namespace osquery
