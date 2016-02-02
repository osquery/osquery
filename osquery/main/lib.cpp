/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <osquery/core.h>

// If CMake/gmake did not define a build version set the version to 1.0.
// clang-format off
#ifndef OSQUERY_BUILD_VERSION
#define OSQUERY_BUILD_VERSION 1.0.0-unknown
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
}
