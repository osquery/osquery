/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

#define kIOPCIDeviceClassName_ "IOPCIDevice"

std::string getPCIProperty(const CFMutableDictionaryRef& details,
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

void genPCIDevice(const io_service_t& device, QueryData& results) {
  Row r;

  // Get the device details
  CFMutableDictionaryRef details;
  IORegistryEntryCreateCFProperties(
      device, &details, kCFAllocatorDefault, kNilOptions);

  r["pci_slot"] = getPCIProperty(details, "pcidebug");

  std::vector<std::string> properties;
  auto compatible = getPCIProperty(details, "compatible");
  boost::trim(compatible);
  boost::split(properties, compatible, boost::is_any_of(" "));

  if (properties.size() < 2) {
    VLOG(1) << "Error parsing IOKit compatible properties";
    return;
  }

  size_t prop_index = 0;
  if (properties[1].find("pci") == 0 && properties[1].find("pciclass") != 0) {
    // There are two sets of PCI definitions.
    prop_index = 1;
  } else if (properties[0].find("pci") != 0) {
    VLOG(1) << "No vendor/model found";
    return;
  }

  std::vector<std::string> vendor;
  boost::split(vendor, properties[prop_index++], boost::is_any_of(","));
  r["vendor_id"] = vendor[0].substr(3);
  r["model_id"] = (vendor[1].size() == 3) ? "0" + vendor[1] : vendor[1];

  if (properties[prop_index].find("pciclass") == 0) {
    // There is a class definition.
    r["pci_class"] = properties[prop_index++].substr(9);
  }

  if (properties.size() > prop_index) {
    // There is a driver/ID.
    r["driver"] = properties[prop_index];
  }

  results.push_back(r);
  CFRelease(details);
}

QueryData genPCIDevices(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOPCIDeviceClassName_);
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
    genPCIDevice(device, results);
    IOObjectRelease(device);
  }

  IOObjectRelease(it);
  return results;
}
}
}
