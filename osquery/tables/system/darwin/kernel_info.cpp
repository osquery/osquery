/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/hash.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/efi_misc.h"

namespace osquery {
namespace tables {

#define kIODTChosenPath_ "IODeviceTree:/chosen"

#define MEDIA_DEVICE_PATH 0x04
#define MEDIA_FILEPATH_DP 0x04
#define MEDIA_HARDDRIVE_DP 0x01

std::string getCanonicalEfiDevicePath(const CFDataRef& data) {
  std::string path;

  // Iterate through the EFI_DEVICE_PATH_PROTOCOL stacked structs.
  auto bytes = CFDataGetBytePtr((CFDataRef)data);
  auto length = CFDataGetLength((CFDataRef)data);
  size_t search_offset = 0;

  while ((search_offset + sizeof(EFI_DEVICE_PATH_PROTOCOL)) < length) {
    auto node = (const EFI_DEVICE_PATH_PROTOCOL*)(bytes + search_offset);
    if (EfiIsDevicePathEnd(node)) {
      break;
    }

    if (EfiDevicePathNodeLength(node) + search_offset > length) {
      // Malformed EFI device header.
      break;
    }

    // Only support paths and hard drive partitions.
    if (EfiDevicePathType(node) == MEDIA_DEVICE_PATH) {
      if (node->SubType == MEDIA_FILEPATH_DP) {
        for (size_t i = 0; i < EfiDevicePathNodeLength(node); i += 2) {
          path += (((char*)(node)) + sizeof(EFI_DEVICE_PATH_PROTOCOL))[i];
        }
      } else if (node->SubType == MEDIA_HARDDRIVE_DP) {
        auto hdd = (const HARDDRIVE_DEVICE_PATH*)node;
        boost::uuids::uuid hdd_signature;
        memcpy(&hdd_signature, hdd->Signature, 16);
        path += boost::uuids::to_string(hdd_signature);
      }
    }

    search_offset += EfiDevicePathNodeLength(node);
  }

  return path;
}

QueryData genKernelInfo(QueryContext& context) {
  QueryData results;

  mach_port_t master_port;
  auto kr = IOMasterPort(bootstrap_port, &master_port);
  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Could not get the IOMaster port";
    return {};
  }

  // NVRAM registry entry is :/options.
  auto chosen = IORegistryEntryFromPath(master_port, kIODTChosenPath_);
  if (chosen == 0) {
    VLOG(1) << "Could not get IOKit boot device";
    return {};
  }

  // Parse the boot arguments, usually none.
  CFMutableDictionaryRef properties;
  kr = IORegistryEntryCreateCFProperties(
      chosen, &properties, kCFAllocatorDefault, 0);
  IOObjectRelease(chosen);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Could not get IOKit boot device properties";
    return {};
  }

  Row r;
  CFTypeRef property;
  if (CFDictionaryGetValueIfPresent(
          properties, CFSTR("boot-args"), &property)) {
    r["arguments"] = stringFromCFData((CFDataRef)property);
  }

  if (CFDictionaryGetValueIfPresent(
          properties, CFSTR("boot-device-path"), &property)) {
    r["device"] = getCanonicalEfiDevicePath((CFDataRef)property);
  }

  if (CFDictionaryGetValueIfPresent(
          properties, CFSTR("boot-file"), &property)) {
    r["path"] = stringFromCFData((CFDataRef)property);
  }
  // No longer need chosen properties.
  CFRelease(properties);

  // The kernel version, signature, and build information is stored in Root.
  auto root = IORegistryGetRootEntry(master_port);
  if (root != 0) {
    property = (CFDataRef)IORegistryEntryCreateCFProperty(
        root, CFSTR(kIOKitBuildVersionKey), kCFAllocatorDefault, 0);
    if (property != nullptr) {
      // The version is in the form:
      // Darwin Kernel Version VERSION: DATE; root:BUILD/TAG
      auto signature = stringFromCFString((CFStringRef)property);
      CFRelease(property);

      r["version"] = signature.substr(22, signature.find(":") - 22);
    }
  }

  // With the path and device, try to locate the on-disk kernel
  if (r.count("path") > 0) {
    r["md5"] = hashFromFile(HASH_TYPE_MD5, "/" + r.at("path"));
  }

  results.push_back(r);
  return results;
}
}
}
