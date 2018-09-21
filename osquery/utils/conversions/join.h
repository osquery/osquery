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

#include <string>

#include <boost/algorithm/string.hpp>

namespace osquery {

/**
 * @brief Join a vector of strings inserting a token string between elements
 *
 * @param s the vector of strings to be joined.
 * @param tok a token glue string to be inserted between elements.
 *
 * @return the joined string.
 */
template <typename SequenceType>
inline std::string join(const SequenceType& s, const std::string& tok) {
  return boost::algorithm::join(s, tok);
}

} // namespace osquery
