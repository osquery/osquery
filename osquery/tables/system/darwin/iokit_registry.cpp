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
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/iokit.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

/// A set of common IOKit properties used to store firmware versions.
const std::set<std::string> kFirmwareProperties{
    "Firmware Revision", "IOFirmwareVersion", "FirmwareVersionString",
};

/**
 * @brief A callback for each entry in the IOKit registry.
 *
 * An enumerator should fill in the table's results.
 */
using IOKitEnumerator = std::function<void(const io_service_t& device,
                                           const io_service_t& parent,
                                           const io_name_t plane,
                                           int depth,
                                           QueryData& results)>;

static inline void genFirmware(const void* key, const void* value, void* r) {
  auto* r2 = (Row*)r;
  if (key == nullptr || value == nullptr || r2->count("version") != 0) {
    return;
  }

  auto prop = stringFromCFString((CFStringRef)key);
  if (kFirmwareProperties.find(prop) != kFirmwareProperties.end()) {
    (*r2)["version"] = prop;
  }
}

void genIOKitFirmware(const io_service_t& device,
                      const io_service_t& parent,
                      const io_name_t plane,
                      int depth,
                      QueryData& results) {
  Row r;
  io_name_t name;
  auto kr = IORegistryEntryGetName(device, name);
  if (kr == KERN_SUCCESS) {
    r["device"] = std::string(name);
  }

  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);
  CFDictionaryApplyFunction(details, &genFirmware, &r);
  if (r.count("version") != 0) {
    // If the version is filled in from the dictionary walk callback then
    // the value of the property name contains the firmware version.
    r["version"] = getIOKitProperty(details, r["version"]);
    r["type"] = getIOKitProperty(details, "IOProviderClass");
    results.push_back(r);
  }

  CFRelease(details);
}

void genIOKitDevice(const io_service_t& device,
                    const io_service_t& parent,
                    const io_name_t plane,
                    int depth,
                    QueryData& results) {
  Row r;
  io_name_t name, device_class;
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
}

void genIOKitDeviceChildren(IOKitEnumerator enumerator,
                            const io_registry_entry_t& service,
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
    enumerator(device, service, plane, depth, results);
    genIOKitDeviceChildren(enumerator, device, plane, depth + 1, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
}

QueryData genDeviceFirmware(QueryContext& context) {
  QueryData qd;

  // Start with the services root node.
  auto service = IORegistryGetRootEntry(kIOMasterPortDefault);
  genIOKitDeviceChildren(&genIOKitFirmware, service, kIOServicePlane, 0, qd);
  IOObjectRelease(service);

  return qd;
}

QueryData genIOKitDeviceTree(QueryContext& context) {
  QueryData qd;

  // Get the IO registry root node.
  auto service = IORegistryGetRootEntry(kIOMasterPortDefault);
  // Begin recursing along the IODeviceTree "plane".
  genIOKitDeviceChildren(&genIOKitDevice, service, kIODeviceTreePlane, 0, qd);
  IOObjectRelease(service);

  return qd;
}

QueryData genIOKitRegistry(QueryContext& context) {
  QueryData qd;

  // Get the IO registry root node.
  auto service = IORegistryGetRootEntry(kIOMasterPortDefault);
  // Begin recursing along the IODeviceTree "plane".
  genIOKitDeviceChildren(&genIOKitDevice, service, kIOServicePlane, 0, qd);
  IOObjectRelease(service);

  return qd;
}
}
}
