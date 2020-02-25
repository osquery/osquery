/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#import <Foundation/Foundation.h>
#include <limits.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <stdbool.h>

namespace osquery {
namespace tables {

void logUnsupportedError(std::string vlogMessage) {
  LOG(ERROR) << "This table is not supported on this version of macOS";
  VLOG(1) << vlogMessage;

  return;
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
