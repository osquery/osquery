/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
