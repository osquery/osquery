/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <IOKit/IOKitLib.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key) {
  std::string value;

  // Get a property from the device.
  auto cfkey = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  auto property = CFDictionaryGetValue(details, cfkey);
  CFRelease(cfkey);

  // Several supported ways of parsing IOKit-encoded data.
  if (property) {
    if (CFGetTypeID(property) == CFNumberGetTypeID()) {
      value = stringFromCFNumber((CFDataRef)property);
    } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
      value = stringFromCFString((CFStringRef)property);
    } else if (CFGetTypeID(property) == CFDataGetTypeID()) {
      value = stringFromCFData((CFDataRef)property);
    }
  }

  return value;
}

void genIOKitDevice(const io_service_t& device,
                    const io_service_t& parent,
                    const io_name_t plane,
                    int depth,
                    QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);

  io_name_t name, location, device_class;
  auto kr = IORegistryEntryGetName(device, name);
  if (kr == KERN_SUCCESS) {
    r["name"] = std::string(name);
  }

  // Get the device class.
  kr = IOObjectGetClass(device, device_class);
  if (kr == KERN_SUCCESS) {
    r["class"] = std::string(device_class);
  }

  // The entry into the registry is the ID, and is used for children as parent.
  uint64_t device_id, parent_id;
  kr = IORegistryEntryGetRegistryEntryID(device, &device_id);
  if (kr == KERN_SUCCESS) {
    r["id"] = BIGINT(device_id);
  } else {
    r["id"] = "-1";
  }

  kr = IORegistryEntryGetRegistryEntryID(parent, &parent_id);
  if (kr == KERN_SUCCESS) {
    r["parent"] = BIGINT(parent_id);
  } else {
    r["parent"] = "-1";
  }

  r["depth"] = INTEGER(depth);

  if (IORegistryEntryInPlane(device, kIODeviceTreePlane)) {
    io_string_t device_path;
    kr = IORegistryEntryGetPath(device, kIODeviceTreePlane, device_path);
    if (kr == KERN_SUCCESS) {
      // Remove the "IODeviceTree:" from the device tree path.
      r["device_path"] = std::string(device_path).substr(13);
    }
  }

  // Fill in service bits and busy/latency time.
  if (IOObjectConformsTo(device, "IOService")) {
    r["service"] = "1";
  } else {
    r["service"] = "0";
  }

  uint32_t busy_state;
  kr = IOServiceGetBusyState(device, &busy_state);
  if (kr == KERN_SUCCESS) {
    r["busy_state"] = INTEGER(busy_state);
  } else {
    r["busy_state"] = "0";
  }

  auto retain_count = IOObjectGetKernelRetainCount(device);
  r["retain_count"] = INTEGER(retain_count);

  results.push_back(r);
  CFRelease(details);
}

void genIOKitDeviceChildren(const io_registry_entry_t& service,
                            const io_name_t plane,
                            int depth,
                            QueryData& results) {
  io_iterator_t it;
  auto kr = IORegistryEntryGetChildIterator(service, plane, &it);
  if (kr != KERN_SUCCESS) {
    return;
  }

  io_service_t device;
  while ((device = IOIteratorNext(it))) {
    // Use this entry as the parent, and generate a result row.
    genIOKitDevice(device, service, plane, depth, results);
    genIOKitDeviceChildren(device, plane, depth + 1, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
}

QueryData genIOKitDeviceTree(QueryContext& context) {
  QueryData results;

  // Get the IO registry root node.
  auto service = IORegistryGetRootEntry(kIOMasterPortDefault);

  // Begin recursing along the IODeviceTree "plane".
  genIOKitDeviceChildren(service, kIODeviceTreePlane, 0, results);

  IOObjectRelease(service);
  return results;
}

QueryData genIOKitRegistry(QueryContext& context) {
  QueryData results;

  // Get the IO registry root node.
  auto service = IORegistryGetRootEntry(kIOMasterPortDefault);

  // Begin recursing along the IODeviceTree "plane".
  genIOKitDeviceChildren(service, kIOServicePlane, 0, results);

  IOObjectRelease(service);
  return results;
}
}
}
