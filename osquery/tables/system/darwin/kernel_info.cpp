/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/efi_misc.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/iokit.h>

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
  size_t length = CFDataGetLength((CFDataRef)data);
  size_t search_offset = 0;

  while ((search_offset + sizeof(EFI_DEVICE_PATH_PROTOCOL)) < length) {
    auto node = (const EFI_DEVICE_PATH_PROTOCOL*)(bytes + search_offset);
    if (EfiIsDevicePathEnd(node)) {
      // End of the EFI device path stacked structs.
      break;
    }

    if (EfiDevicePathNodeLength(node) + search_offset > length) {
      // Malformed EFI device header.
      break;
    }

    // Only support paths and hard drive partitions.
    if (EfiDevicePathType(node) == MEDIA_DEVICE_PATH) {
      if (node->SubType == MEDIA_FILEPATH_DP) {
        for (int i = 0; i < EfiDevicePathNodeLength(node); i += 2) {
          // Strip UTF16 characters to UTF8.
          path += (((char*)(node)) + sizeof(EFI_DEVICE_PATH_PROTOCOL))[i];
        }
      } else if (node->SubType == MEDIA_HARDDRIVE_DP) {
        // Extract the device UUID to later join with block devices.
        auto uuid = ((const HARDDRIVE_DEVICE_PATH*)node)->Signature;
        // clang-format off
        boost::uuids::uuid hdd_signature = {{
          uuid[3], uuid[2], uuid[1], uuid[0],
          uuid[5], uuid[4],
          uuid[7], uuid[6],
          uuid[8], uuid[9],
          uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
        }};
        // clang-format on

        path += boost::to_upper_copy(boost::uuids::to_string(hdd_signature));
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
    std::replace(r["path"].begin(), r["path"].end(), '\\', '/');
    boost::trim(r["path"]);
    if (!r["path"].empty() && r["path"][0] != '/') {
      r["path"] = "/" + r["path"];
    }
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

      r["version"] = signature.substr(22, signature.find(':') - 22);
    }
  }

  results.push_back(r);
  return results;
}
}
}
