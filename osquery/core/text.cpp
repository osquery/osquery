// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <glog/logging.h>

namespace osquery { namespace core {

std::vector<std::string> split(const std::string& s) {
  return split(s, "\t ");
}

std::vector<std::string> split(const std::string& s,
  const std::string& delim) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(delim));
  auto start = std::remove_if(elems.begin(), elems.end(),
    std::bind1st(std::equal_to<std::string>(), std::string(""))
  );
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    boost::algorithm::trim(each);

  }
  return elems;
}

}}
