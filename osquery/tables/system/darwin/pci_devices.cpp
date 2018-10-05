/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/core/darwin/iokit.hpp"

namespace osquery {
namespace tables {

void genPCIDevice(const io_service_t& device, QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);

  r["pci_slot"] = getIOKitProperty(details, "pcidebug");

  auto compatible = getIOKitProperty(details, "compatible");
  auto properties = IOKitPCIProperties(compatible);
  r["vendor_id"] = properties.vendor_id;
  r["model_id"] = properties.model_id;
  r["pci_class"] = properties.pci_class;
  r["driver"] = properties.driver;

  results.push_back(r);
  CFRelease(details);
}

QueryData genPCIDevices(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOPCIDeviceClassName_.c_str());
  if (matching == nullptr) {
    // No devices matched PCI, very odd.
    return results;
  }

  io_iterator_t it;
  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return results;
  }

  io_service_t device;
  while ((device = IOIteratorNext(it))) {
    genPCIDevice(device, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
  return results;
}
}
}
