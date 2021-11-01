/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/env.h>

#include <string>
#include <boost/optional.hpp>

#include <stdlib.h>
#include <wordexp.h>

namespace osquery {

bool setEnvVar(const std::string& name, const std::string& value) {
  auto ret = ::setenv(name.c_str(), value.c_str(), 1);
  return (ret == 0);
}

bool unsetEnvVar(const std::string& name) {
  auto ret = ::unsetenv(name.c_str());
  return (ret == 0);
}

boost::optional<std::string> getEnvVar(const std::string& name) {
  char* value = ::getenv(name.c_str());
  if (value) {
    return std::string(value);
  }
  return boost::none;
}

boost::optional<std::string> expandEnvString(const std::string& input) {
  wordexp_t p;
  int result = wordexp(input.c_str(), &p, WRDE_NOCMD | WRDE_UNDEF);
  if (result) {
    VLOG(1) << "Failed to expand environment string: " << result;
    return boost::none;
  }
  std::stringstream expandedString;
  for (size_t i = 0; i < p.we_wordc; i++) {
    if (i > 0) {
      expandedString << " ";
    }
    expandedString << p.we_wordv[i];
  }

  wordfree(&p);
  return expandedString.str();
}

} // namespace osquery
