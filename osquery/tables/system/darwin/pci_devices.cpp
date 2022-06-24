/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

void genPCIDevice(const io_service_t& device, QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  auto ret = IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);
  if (ret != KERN_SUCCESS) {
    return;
  }
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
} // namespace tables
} // namespace osquery
