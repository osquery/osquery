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
#include <IOKit/usb/IOUSBLib.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

std::string getUSBProperty(const CFMutableDictionaryRef& details,
                           const std::string& key) {
  // Get a property from the device.
  auto cfkey = CFStringCreateWithCString(kCFAllocatorDefault, key.c_str(),
    kCFStringEncodingUTF8);
  auto property = CFDictionaryGetValue(details, cfkey);
  CFRelease(cfkey);
  if (property) {
    if (CFGetTypeID(property) == CFNumberGetTypeID()) {
      return stringFromCFNumber((CFDataRef)property);
    } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
      return stringFromCFString((CFStringRef)property);
    }
  }
  return "";
}

void genUSBDevice(const io_service_t& device, QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);

  r["usb_address"] = getUSBProperty(details, "USB Address");
  r["usb_port"] = getUSBProperty(details, "PortNum");

  r["model"] = getUSBProperty(details, "USB Product Name");
  r["model_id"] = getUSBProperty(details, "idProduct");
  r["vendor"] = getUSBProperty(details, "USB Vendor Name");
  r["vendor_id"] = getUSBProperty(details, "idVendor");
  r["serial"] = getUSBProperty(details, "iSerialNumber");

  auto non_removable = getUSBProperty(details, "non-removable");
  r["removable"] = (non_removable == "yes") ? "0" : "1";

  results.push_back(r);
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
