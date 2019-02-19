/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <type_traits>

namespace osquery {

/**
 * This is just a ad-hoc fix up to handle libc++ and libstdc++ bug:
 * http://www.open-std.org/jtc1/sc22/wg21/docs/lwg-defects.html#2148
 * Eventually it will be removed.
 */
struct EnumClassHash {
  template <typename EnumClassType>
  typename std::enable_if<std::is_enum<EnumClassType>::value, std::size_t>::type
  operator()(EnumClassType t) const {
    return static_cast<std::size_t>(t);
  }
};

} // namespace osquery
