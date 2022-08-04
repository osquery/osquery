/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <iomanip>

#include <boost/algorithm/string.hpp>

#include <osquery/utils/conversions/tryto.h>

#include "cfdata.h"
#include "cfnumber.h"
#include "cfstring.h"
#include "iokit.h"

namespace osquery {

const std::string kIOUSBDeviceClassName_ = "IOUSBDevice";
const std::string kIOPCIDeviceClassName_ = "IOPCIDevice";
const std::string kIOPlatformExpertDeviceClassName_ = "IOPlatformExpertDevice";
const std::string kIOACPIPlatformDeviceClassName_ = "IOACPIPlatformDevice";
const std::string kIOPlatformDeviceClassName_ = "IOPlatformDevice";
const std::string kAppleARMIODeviceClassName_ = "AppleARMIODevice";

IOKitPCIProperties::IOKitPCIProperties(const std::string& compatible) {
  std::vector<std::string> properties;
  boost::split(properties, compatible, boost::is_any_of(" "));
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

  std::vector<std::string> vendor;
  boost::split(vendor, properties[prop_index++], boost::is_any_of(","));
  if (!vendor.empty()) {
    vendor_id = vendor[0].substr(3);
    if (vendor.size() > 1) {
      model_id = (vendor[1].size() == 3) ? "0" + vendor[1] : vendor[1];
    }
  }

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
  if (!property) {
    return value;
  }

  if (CFGetTypeID(property) == CFNumberGetTypeID()) {
    value = stringFromCFNumber((CFDataRef)property);
  } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
    value = stringFromCFString((CFStringRef)property);
  } else if (CFGetTypeID(property) == CFDataGetTypeID()) {
    value = stringFromCFData((CFDataRef)property);
  } else if (CFGetTypeID(property) == CFBooleanGetTypeID()) {
    value = (CFBooleanGetValue((CFBooleanRef)property)) ? "1" : "0";
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

void idToHex(std::string& id) {
  auto const base_exp = tryTo<long>(id, 10);
  if (base_exp.isValue()) {
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0')
           << (base_exp.get() & 0xFFFF);
    id = hex_id.str();
  }
}

} // namespace osquery
