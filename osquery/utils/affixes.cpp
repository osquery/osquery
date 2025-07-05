/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "affixes.h"

#include <boost/algorithm/cxx11/any_of.hpp>
#include <boost/algorithm/string/predicate.hpp>

namespace osquery {

bool hasAnyPrefix(const std::string& s,
                  const std::vector<std::string>& prefixes) {
  return boost::algorithm::any_of(prefixes, [&s](const auto& prefix) {
    return boost::algorithm::starts_with(s, prefix);
  });
}

bool hasAnySuffix(const std::string& s,
                  const std::vector<std::string>& suffixes) {
  return boost::algorithm::any_of(suffixes, [&s](const auto& suffix) {
    return boost::algorithm::ends_with(s, suffix);
  });
}

} // namespace osquery
