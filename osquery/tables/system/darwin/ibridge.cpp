/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/darwin/iokit.hpp"

namespace osquery {
namespace tables {

#define kIODeviceEfiPath_ ":/efi/platform"
#define kEmbeddedOSClass_ "AppleEmbeddedOSSupportHost"
#define kAppleCoprocessorVersionKey_ "apple-coprocessor-version"

/// as defined in
/// /System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOPlatformExpert.h
static const std::map<uint32_t, std::string> kCoprocessorVersions = {
    {0x00000000, ""},
    {0x00010000, "Apple T1 Chip"},
    {0x00020000, "Apple T2 Chip"},
};

static inline void genAppleCoprocessorVersion(Row& r) {
  auto asoc = IORegistryEntryFromPath(kIOMasterPortDefault,
                                      kIODeviceTreePlane kIODeviceEfiPath_);
  if (asoc == MACH_PORT_NULL) {
    VLOG(1) << "Cannot open EFI Device Tree";
    return;
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      asoc, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(asoc);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Cannot get EFI properties";
    return;
  }

  if (CFDictionaryContainsKey(properties,
                              CFSTR(kAppleCoprocessorVersionKey_))) {
    auto version_data = (CFDataRef)CFDictionaryGetValue(
        properties, CFSTR(kAppleCoprocessorVersionKey_));
    auto range = CFRangeMake(0, CFDataGetLength(version_data));
    auto buffer = (unsigned char*)malloc(range.length + 1);

    if (buffer == nullptr) {
      return;
    }
    memset(buffer, 0, range.length + 1);
    CFDataGetBytes(version_data, range, buffer);

    uint32_t version = {0};
    memcpy(&version, buffer, 4);

    r["coprocessor_version"] = (kCoprocessorVersions.count(version) > 0)
                                   ? kCoprocessorVersions.at(version)
                                   : "unknown";
    free(buffer);
  }
  CFRelease(properties);
}

QueryData genIBridgeInfo(QueryContext& context) {
  QueryData results;
  Row r;

  genAppleCoprocessorVersion(r);

  auto eos = IOServiceNameMatching(kEmbeddedOSClass_);
  if (eos == nullptr) {
    VLOG(1)
        << "EmbeddedOS class not found. Perhaps this mac doesn't have T* chip";
    return results;
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, eos);
  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      service, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(service);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Cannot get EmbeddedOS properties";
    IOObjectRelease(service);
    return results;
  }

  r["unique_chip_id"] = getIOKitProperty(properties, "DeviceUniqueChipID");
  r["firmware_version"] = getIOKitProperty(properties, "DeviceBuildVersion");
  r["boot_uuid"] = getIOKitProperty(properties, "DeviceBootUUID");

  CFRelease(properties);
  IOObjectRelease(service);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
