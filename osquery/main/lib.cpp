/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

// If CMake/gmake did not define a build version set the version to 1.0.
// clang-format off
#if !defined(OSQUERY_BUILD_VERSION)
#warning The build should define OSQUERY_BUILD_VERSION.
#define OSQUERY_BUILD_VERSION 1.0.0-unknown
#endif
#if !defined(OSQUERY_PLATFORM_MASK)
#error The build must define OSQUERY_PLATFORM_MASK.
#endif
// clang-format on

namespace osquery {

#ifdef DEBUG
const std::string kVersion = CONCAT(OSQUERY_BUILD_VERSION, -debug);
#else
const std::string kVersion = STR(OSQUERY_BUILD_VERSION);
#endif
const std::string kSDKVersion = OSQUERY_SDK_VERSION;
const std::string kSDKPlatform = OSQUERY_PLATFORM;
const PlatformType kPlatformType =
    static_cast<PlatformType>(OSQUERY_PLATFORM_MASK);

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
    } catch (const std::invalid_argument& e) {
      VLOG(1) << "Failed to parse version number: " << e.what();
      if (chunk.compare(required_version[index]) < 0) {
        return false;
      }
    }
    index++;
  }
  return true;
}
}
