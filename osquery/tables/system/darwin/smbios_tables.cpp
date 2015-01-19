/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/tables.h>

#include "osquery/tables/system/smbios_utils.h"

namespace osquery {
namespace tables {

#define kIOSMBIOSClassName_ "AppleSMBIOS"
#define kIOSMBIOSPropertyName_ "SMBIOS"
#define kIOSMBIOSEPSPropertyName_ "SMBIOS-EPS"

QueryData genSMBIOSTables(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOSMBIOSClassName_);
  if (matching == nullptr) {
    // No ACPI platform expert service found.
    return {};
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  if (service == 0) {
    return {};
  }

  // Unlike ACPI the SMBIOS property will return several structures
  // followed by a table of structured entries (also called tables).
  // http://dmtf.org/sites/default/files/standards/documents/DSP0134_2.8.0.pdf
  CFTypeRef smbios = IORegistryEntryCreateCFProperty(
      service, CFSTR(kIOSMBIOSPropertyName_), kCFAllocatorDefault, 0);
  if (smbios == nullptr) {
    IOObjectRelease(service);
    return {};
  }

  // Check the first few SMBIOS structures before iterating through tables.
  const uint8_t* smbios_data = CFDataGetBytePtr((CFDataRef)smbios);
  size_t length = CFDataGetLength((CFDataRef)smbios);

  if (smbios_data == nullptr || length == 0) {
    // Problem creating SMBIOS property.
    IOObjectRelease(service);
    return {};
  }

  // Parse structures.
  genSMBIOSTables(smbios_data, length, results);

  CFRelease(smbios);
  IOObjectRelease(service);
  return results;
}
}
}
