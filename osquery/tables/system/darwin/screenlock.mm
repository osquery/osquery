/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <Foundation/Foundation.h>
#include <limits.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <stdbool.h>

namespace osquery {
namespace tables {

void logUnsupportedError(const std::string& reason) {
  LOG(ERROR)
      << "The screenlock table is not supported on this version of macOS: "
      << reason;
}

QueryData genScreenlock(QueryContext& context) {
  QueryData results;
  Row r;

  auto bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/MobileKeyBag.framework"),
      kCFURLPOSIXPathStyle,
      true);

  if (bundle_url == nullptr) {
    logUnsupportedError("Error parsing MobileKeyBag bundle URL");

    return results;
  }

  auto bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);

  if (bundle == nullptr) {
    logUnsupportedError("Error opening MobileKeyBag bundle");

    return results;
  }

  auto MKBDeviceGetGracePeriod =
      (NSDictionary * (*)(NSDictionary*)) CFBundleGetFunctionPointerForName(
          bundle, CFSTR("MKBDeviceGetGracePeriod"));
  if (MKBDeviceGetGracePeriod == nullptr) {
    logUnsupportedError("MKBDeviceGetGracePeriod returned null");
    CFRelease(bundle);

    return results;
  }

  // MKBDeviceGetGracePeriod requires an empty dictionary as the sole argument
  NSDictionary* durationDict = MKBDeviceGetGracePeriod(@{});
  if (![durationDict isKindOfClass:[NSDictionary class]]) {
    VLOG(1) << "MKBDeviceGetGracePeriod did not return an NSDictionary";
    CFRelease(bundle);
    return results;
  }

  NSNumber* durationNumber = durationDict[@"GracePeriod"];
  if (![durationNumber isKindOfClass:[NSNumber class]]) {
    VLOG(1) << "GracePeriod did not contain an NSNumber";
    CFRelease(bundle);
    return results;
  }

  int duration = durationNumber.integerValue;
  // A value of INT_MAX indicates that the lock is disabled
  int enabled = (duration == INT_MAX) ? 0 : 1;
  // Return -1 for grace_period when the lock is not set
  int grace_period = enabled == 0 ? -1 : duration;

  r["enabled"] = INTEGER(enabled);
  r["grace_period"] = INTEGER(grace_period);

  results.push_back(r);
  CFRelease(bundle);
  return results;
}
} // namespace tables
} // namespace osquery
