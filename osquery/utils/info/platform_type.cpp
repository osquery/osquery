/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/utils/info/platform_type.h>

namespace osquery {

const std::string kSDKPlatform = OSQUERY_PLATFORM;

/// Helper method for platform type detection.
bool isPlatform(PlatformType a, const PlatformType& t) {
  return (static_cast<int>(t) & static_cast<int>(a)) != 0;
}

PlatformType operator|(PlatformType a, PlatformType b) {
  return static_cast<PlatformType>(static_cast<int>(a) | static_cast<int>(b));
}

} // namespace osquery
