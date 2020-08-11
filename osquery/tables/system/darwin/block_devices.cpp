/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <DiskArbitration/DADisk.h>
#include <DiskArbitration/DASession.h>

#include <boost/lexical_cast.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

#define kIOMediaClassName_ "IOMedia"

void genIOMediaDevice(const io_service_t& device,
                      std::vector<std::string>& whole_devices,
                      QueryData& results) {
  Row r;

  // Get the device properties
  CFMutableDictionaryRef properties;
  IORegistryEntryCreateCFProperties(
      device, &properties, kCFAllocatorDefault, kNilOptions);

  r["uuid"] = getIOKitProperty(properties, "UUID");
  r["name"] = "/dev/" + getIOKitProperty(properties, "BSD Name");
  r["block_size"] = getIOKitProperty(properties, "Preferred Block Size");
  auto disk_size = getNumIOKitProperty(properties, "Size");
  auto block_size = getNumIOKitProperty(properties, "Preferred Block Size");
  r["size"] = boost::lexical_cast<std::string>(disk_size / block_size);
  auto type = getIOKitProperty(properties, "Whole");
  if (type == "1") {
    // The "Whole" property applies to the entire disk entry, not partitions.
    whole_devices.push_back(r["name"]);
  } else {
    // Otherwise search the list of whole disks to find the node parent.
    for (const auto& parent : whole_devices) {
      if (r.at("name").find(parent) == 0) {
        r["parent"] = parent;
      }
    }
  }

  // This is the IOKit name, which is the device's label.
  io_name_t name;
  auto kr = IORegistryEntryGetName(device, name);
  if (kr == KERN_SUCCESS && (char*)name != nullptr) {
    r["label"] = std::string(name);
  }

  // Remaining details come from the Disk Arbitration service.
  DASessionRef session = DASessionCreate(kCFAllocatorDefault);
  CFDictionaryRef details;
  if (session != nullptr) {
    auto disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, session, device);
    if (disk != nullptr) {
      details = DADiskCopyDescription(disk);
      if (details != nullptr) {
        r["vendor"] =
            getIOKitProperty((CFMutableDictionaryRef)details, "DADeviceVendor");
        r["model"] =
            getIOKitProperty((CFMutableDictionaryRef)details, "DADeviceModel");
        r["type"] = getIOKitProperty((CFMutableDictionaryRef)details,
                                     "DADeviceProtocol");
        CFRelease(details);
      }
      CFRelease(disk);
    }
    CFRelease(session);
  }

  results.push_back(r);
  CFRelease(properties);
}

QueryData genBlockDevs(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOMediaClassName_);
  if (matching == nullptr) {
    // No devices matched IOMedia.
    return {};
  }

  io_iterator_t it;
  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return {};
  }

  std::vector<std::string> whole_devices;

  io_service_t device;
  while ((device = IOIteratorNext(it))) {
    genIOMediaDevice(device, whole_devices, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
  return results;
}
}
}
