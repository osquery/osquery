/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <IOKit/usb/IOUSBLib.h>

#include <osquery/core/tables.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

std::string decodeUSBBCD(uint16_t bcd) {
  uint8_t array[2];
  array[0] = bcd & 0xff;
  array[1] = (bcd >> 8);
  uint8_t major = ((array[1] / 16 * 10) + (array[1] % 16));
  uint8_t minor = ((array[0] / 16 * 10) + (array[0] % 16));
  return std::to_string(major) + "." + std::to_string(minor);
}

void genUSBDevice(const io_service_t& device, QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);

  r["usb_address"] = getIOKitProperty(details, "USB Address");
  r["usb_port"] = getIOKitProperty(details, "PortNum");

  r["model"] = getIOKitProperty(details, "USB Product Name");
  if (r.at("model").size() == 0) {
    // Could not find the model name from IOKit, use the label.
    io_name_t name;
    if (IORegistryEntryGetName(device, name) == KERN_SUCCESS) {
      r["model"] = std::string(name);
    }
  }

  r["model_id"] = getIOKitProperty(details, "idProduct");
  r["vendor"] = getIOKitProperty(details, "USB Vendor Name");
  r["vendor_id"] = getIOKitProperty(details, "idVendor");
  r["version"] = decodeUSBBCD(getNumIOKitProperty(details, "bcdDevice"));

  r["class"] =
      std::to_string(getNumIOKitProperty(details, "bDeviceClass") & 0xFF);
  r["subclass"] =
      std::to_string(getNumIOKitProperty(details, "bDeviceSubClass") & 0xFF);

  r["serial"] = getIOKitProperty(details, "USB Serial Number");
  if (r.at("serial").size() == 0) {
    r["serial"] = getIOKitProperty(details, "iSerialNumber");
  }

  auto non_removable = getIOKitProperty(details, "non-removable");
  r["removable"] = (non_removable == "yes") ? "0" : "1";

  if (r.at("vendor_id").size() > 0 && r.at("model_id").size() > 0) {
    // Only add the USB device on OS X if it contains a Vendor and Model ID.
    // On OS X 10.11 the simulation hubs are PCI devices within IOKit and
    // lack the useful USB metadata.
    idToHex(r["vendor_id"]);
    idToHex(r["model_id"]);
    results.push_back(r);
  }
  CFRelease(details);
}

QueryData genUSBDevices(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOUSBDeviceClassName);
  if (matching == nullptr) {
    // No devices matched USB, very odd.
    return results;
  }

  io_iterator_t it;
  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return results;
  }

  io_service_t device;
  while ((device = IOIteratorNext(it))) {
    genUSBDevice(device, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
  return results;
}
}
}
