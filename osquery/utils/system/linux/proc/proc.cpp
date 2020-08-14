/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/proc/proc.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>

namespace osquery {
namespace proc {

namespace fs = boost::filesystem;

namespace {

inline fs::path attrPath(const std::string& pid, char const* attr) {
  auto attr_path = fs::path("/proc");
  attr_path /= pid;
  attr_path /= attr;
  return attr_path;
}

inline fs::path attrPath(pid_t pid, char const* attr) {
  return attrPath(std::to_string(pid), attr);
}

} // namespace

std::string cmdline(pid_t const pid) {
  auto attr_path = attrPath(pid, "cmdline");
  auto ifs = std::ifstream(attr_path.c_str(),
                           std::ios_base::in | std::ios_base::binary);
  using iter = std::istreambuf_iterator<std::string::value_type>;
  auto content = std::string{iter(ifs), iter{}};

  // According to kernel docs the command-line arguments appear in this string
  // as a set of strings separated by null bytes ('\0'), with a further null
  // byte after the last string. Let's get rid of them.
  std::replace(content.begin(), content.end(), '\0', ' ');
  boost::algorithm::trim_right(content);
  return content;
}

} // namespace proc
} // namespace osquery
