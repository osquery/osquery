// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <algorithm>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

#include <glog/logging.h>

namespace osquery { namespace core {

std::vector<std::string> splitString(const std::string& s, const char delim) {
  std::vector<std::string> elems;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    elems.push_back(item);
  }
  auto start = std::remove_if(elems.begin(), elems.end(),
    std::bind1st(std::equal_to<std::string>(), std::string(""))
  );
  elems.erase(start, elems.end());
  return elems;
}

std::string joinString(const std::vector<std::string>& v, const char delim) {
  std::stringstream result;
  int c = 0;
  for (const auto& i : v) {
    result << i;
    ++c;
    if (c < v.size()) {
      result << delim;
    }
  }
  return result.str();
}

}}
