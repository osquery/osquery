/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
