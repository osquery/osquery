/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/info/version.h>
#include <osquery/utils/conversions/split.h>

#include <stdexcept>
#include <stdexcept>

namespace osquery {

const std::string kVersion = STR(OSQUERY_VERSION);
const std::string kSDKVersion = STR(OSQUERY_BUILD_SDK_VERSION);

bool versionAtLeast(const std::string& v, const std::string& sdk) {
  if (v == "0.0.0" || sdk == "0.0.0") {
    // This is a please-pass check.
    return true;
  }

  auto required_version = split(v, ".");
  auto build_version = split(sdk, ".");

  size_t index = 0;
  for (const auto& chunk : build_version) {
    if (required_version.size() <= index) {
      return true;
    }
    try {
      if (std::stoi(chunk) < std::stoi(required_version[index])) {
        return false;
      } else if (std::stoi(chunk) > std::stoi(required_version[index])) {
        return true;
      }
    } catch (const std::invalid_argument& /* e */) {
      if (chunk.compare(required_version[index]) < 0) {
        return false;
      }
    }
    index++;
  }
  return true;
}

} // namespace osquery
