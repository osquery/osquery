/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>

#include <osquery/core.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace osquery {

std::vector<std::string> split(const std::string& s, const std::string& delim) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(delim));
  auto start = std::remove_if(
      elems.begin(), elems.end(), [](const std::string& s) { return s == ""; });
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    boost::algorithm::trim(each);
  }
  return elems;
}

std::vector<std::string> split(const std::string& s,
                               const std::string& delim,
                               size_t occurences) {
  // Split the string normally with the required delimiter.
  auto content = split(s, delim);
  // While the result split exceeds the number of requested occurences, join.
  std::vector<std::string> accumulator;
  std::vector<std::string> elems;
  for (size_t i = 0; i < content.size(); i++) {
    if (i < occurences) {
      elems.push_back(content.at(i));
    } else {
      accumulator.push_back(content.at(i));
    }
  }
  // Join the optional accumulator.
  if (accumulator.size() > 0) {
    elems.push_back(join(accumulator, delim));
  }
  return elems;
}

std::string join(const std::vector<std::string>& s, const std::string& tok) {
  return boost::algorithm::join(s, tok);
}
}
