/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>
#include <osquery/tables.h>

#include <IOKit/IOMessage.h>

#include "osquery/core/conversions.h"
#include "osquery/core/darwin/iokit.hpp"

namespace osquery {

const std::string kIOUSBDeviceClassName_ = "IOUSBDevice";
const std::string kIOPCIDeviceClassName_ = "IOPCIDevice";
const std::string kIOPlatformExpertDeviceClassName_ = "IOPlatformExpertDevice";
const std::string kIOACPIPlatformDeviceClassName_ = "IOACPIPlatformDevice";
const std::string kIOPlatformDeviceClassname_ = "IOPlatformDevice";


IOKitPCIProperties::IOKitPCIProperties(const std::string& compatible) {
  auto properties = osquery::split(compatible, " ");
  if (properties.size() < 2) {
    return;
  }

  size_t prop_index = 0;
  if (properties[1].find("pci") == 0 && properties[1].find("pciclass") != 0) {
    // There are two sets of PCI definitions.
    prop_index = 1;
  } else if (properties[0].find("pci") != 0) {
    return;
  }

  auto vendor = osquery::split(properties[prop_index++], ",");
  vendor_id = vendor[0].substr(3);
  model_id = (vendor[1].size() == 3) ? "0" + vendor[1] : vendor[1];

  if (properties[prop_index].find("pciclass") == 0) {
    // There is a class definition.
    pci_class = properties[prop_index++].substr(9);
  }

  if (properties.size() > prop_index) {
    // There is a driver/ID.
    driver = properties[prop_index];
  }
}

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
    } else if (CFGetTypeID(property) == CFBooleanGetTypeID()) {
      value = (CFBooleanGetValue((CFBooleanRef)property)) ? "1" : "0";
    }
  }

  return value;
}

long long int getNumIOKitProperty(const CFMutableDictionaryRef& details,
                                  const std::string& key) {
  // Get a property from the device.
  auto cfkey = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  auto property = CFDictionaryGetValue(details, cfkey);
  CFRelease(cfkey);

  // Several supported ways of parsing IOKit-encoded data.
  if (property && CFGetTypeID(property) == CFNumberGetTypeID()) {
    CFNumberType type = CFNumberGetType((CFNumberRef)property);
    long long int value;
    CFNumberGetValue((CFNumberRef)property, type, &value);
    return value;
  }

  return 0;
}


}
