/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

#define kIODeviceEfiPath_ ":/efi/platform"
#define kIODeviceChosenPath_ ":/chosen"
#define kEmbeddedOSClass_ "AppleEmbeddedOSSupportHost"
#define kAppleCoprocessorVersionKey_ "apple-coprocessor-version"

/// as defined in
/// /System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOPlatformExpert.h
static const std::unordered_map<uint32_t, std::string> kCoprocessorVersions = {
    {0x00000000, ""},
    {0x00010000, "Apple T1 Chip"},
    {0x00020000, "Apple T2 Chip"},
};

static inline void genBootUuid(Row& r) {
  auto chosen = IORegistryEntryFromPath(
      kIOMasterPortDefault, kIODeviceTreePlane kIODeviceChosenPath_);
  if (chosen == MACH_PORT_NULL) {
    return;
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      chosen, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(chosen);

  if (kr != KERN_SUCCESS) {
    LOG(WARNING) << "Cannot get EFI properties";
    if (properties != nullptr) {
      CFRelease(properties);
    }
    return;
  }

  r["boot_uuid"] = getIOKitProperty(properties, "boot-uuid");
  CFRelease(properties);
}

static inline void genAppleCoprocessorVersion(Row& r) {
  auto asoc = IORegistryEntryFromPath(kIOMasterPortDefault,
                                      kIODeviceTreePlane kIODeviceEfiPath_);
  if (asoc == MACH_PORT_NULL) {
    LOG(WARNING) << "Cannot open EFI Device Tree";
    return;
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      asoc, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(asoc);

  if (kr != KERN_SUCCESS) {
    LOG(WARNING) << "Cannot get EFI properties";
    if (properties != nullptr) {
      CFRelease(properties);
    }
    return;
  }

  if (CFDictionaryContainsKey(properties,
                              CFSTR(kAppleCoprocessorVersionKey_))) {
    auto version_data = (CFDataRef)CFDictionaryGetValue(
        properties, CFSTR(kAppleCoprocessorVersionKey_));
    auto range = CFRangeMake(0, CFDataGetLength(version_data));

    auto buffer = std::vector<unsigned char>(range.length + 1, 0);
    CFDataGetBytes(version_data, range, &buffer[0]);

    uint32_t version = 0;
    memcpy(&version, buffer.data(), sizeof(uint32_t));
    r["coprocessor_version"] = (kCoprocessorVersions.count(version) > 0)
                                   ? kCoprocessorVersions.at(version)
                                   : "unknown";
  }
  CFRelease(properties);
}

QueryData genIBridgeInfo(QueryContext& context) {
  QueryData results;
  Row r;

  genAppleCoprocessorVersion(r);
  genBootUuid(r);

  auto eos = IOServiceNameMatching(kEmbeddedOSClass_);
  if (eos == nullptr) {
    LOG(WARNING)
        << "EmbeddedOS class not found. Perhaps this mac doesn't have T* chip";
    return results;
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, eos);
  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      service, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(service);

  if (kr != KERN_SUCCESS) {
    LOG(WARNING) << "Cannot get EmbeddedOS properties";
    if (properties != nullptr) {
      CFRelease(properties);
    }
    return results;
  }

  r["unique_chip_id"] = getIOKitProperty(properties, "DeviceUniqueChipID");
  r["firmware_version"] = getIOKitProperty(properties, "DeviceBuildVersion");

  CFRelease(properties);

  results.push_back(std::move(r));
  return results;
}
} // namespace tables
} // namespace osquery
