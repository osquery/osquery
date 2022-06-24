/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "split.h"

#include <boost/algorithm/string.hpp>

namespace osquery {

std::vector<std::string> split(const std::string& s, const std::string& delim) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(delim));
  auto start =
      std::remove_if(elems.begin(), elems.end(), [](const std::string& t) {
        return t.size() == 0;
      });
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    boost::algorithm::trim(each);
  }
  return elems;
}

std::vector<std::string> split(const std::string& s,
                               char delim,
                               size_t occurrences) {
  auto delims = std::string(1, delim);
  // Split the string normally with the required delimiter.
  auto content = split(s, delims);
  // While the result split exceeds the number of requested occurrences, join.
  std::vector<std::string> accumulator;
  std::vector<std::string> elems;
  for (size_t i = 0; i < content.size(); i++) {
    if (i < occurrences) {
      elems.push_back(content.at(i));
    } else {
      accumulator.push_back(content.at(i));
    }
  }
  // Join the optional accumulator.
  if (accumulator.size() > 0) {
    elems.push_back(boost::algorithm::join(accumulator, delims));
  }
  return elems;
}

std::vector<std::string_view> vsplit(const std::string_view source,
                                     char delimiter) {
  if (source.empty()) {
    return {};
  }

  std::size_t start = source.find_first_not_of(delimiter);

  if (start == std::string_view::npos) {
    return {};
  }

  std::vector<std::string_view> elements;
  std::size_t end = std::string_view::npos;

  do {
    end = source.find(delimiter, start);

    if (end == std::string_view::npos) {
      elements.emplace_back(source.substr(start));
    } else if (start != end) {
      elements.emplace_back(source.substr(start, end - start));
    }

    start = end + 1;

  } while (end != std::string_view::npos && start < source.size());

  return elements;
}

} // namespace osquery
