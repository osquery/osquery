/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "tryto.h"

#include <unordered_map>

#include <boost/io/quoted.hpp>

namespace osquery {

namespace impl {

Expected<bool, ConversionError> stringToBool(std::string from) {
  static const auto table = std::unordered_map<std::string, bool>{
      {"1", true},
      {"0", false},
      {"y", true},
      {"yes", true},
      {"n", false},
      {"no", false},
      {"t", true},
      {"true", true},
      {"f", false},
      {"false", false},
      {"ok", true},
      {"disable", false},
      {"enable", true},
      {"on", true},
      {"off", false},
  };
  using CharType = std::string::value_type;
  // Classic locale could be used here because all available string
  // representations of boolean have ascii encoding. It must be a bit faster.
  static const auto& ctype =
      std::use_facet<std::ctype<CharType>>(std::locale::classic());
  for (auto& ch : from) {
    ch = ctype.tolower(ch);
  }
  const auto it = table.find(from);
  if (it == table.end()) {
    return createError(ConversionError::InvalidArgument)
           << "Wrong string representation of boolean "
           << boost::io::quoted(from);
  }
  return it->second;
}

} // namespace impl

} // namespace osquery
