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
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <glog/logging.h>

namespace osquery { namespace core {

std::vector<std::string> split(const std::string& s) {
  return split(s, "\t ");
}

std::vector<std::string> split(const std::string& s,
  const std::string& regexp) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(regexp));
  auto start = std::remove_if(elems.begin(), elems.end(),
    std::bind1st(std::equal_to<std::string>(), std::string(""))
  );
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    trim(each);
  }
  return elems;
}

std::string join(const std::vector<std::string>& v, const std::string& delim) {
  return boost::algorithm::join(v, delim);
}

std::string& ltrim(std::string &s) {
  s.erase(
    s.begin(),
    std::find_if(
      s.begin(),
      s.end(),
      std::not1(std::ptr_fun<int, int>(std::isspace))
    )
  );
  return s;
}

std::string& rtrim(std::string &s) {
  s.erase(
    std::find_if(
      s.rbegin(),
      s.rend(),
      std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
    s.end()
  );
  return s;
}

std::string& trim(std::string &s) {
  return ltrim(rtrim(s));
}

}}
