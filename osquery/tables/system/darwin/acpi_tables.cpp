/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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

#include "osquery/core/conversions.h"
#include "osquery/tables/system/hash.h"

namespace osquery {
namespace tables {

#define kIOACPIClassName_ "AppleACPIPlatformExpert"
#define kIOACPIPropertyName_ "ACPI Tables"

void genACPITable(const void* key, const void* value, void* results) {
  Row r;
  auto data = (CFDataRef)value;
  auto length = CFDataGetLength(data);

  r["name"] = stringFromCFString((CFStringRef)key);
  r["size"] = INTEGER(length);
  r["md5"] = hashFromBuffer(HASH_TYPE_MD5, CFDataGetBytePtr(data), length);

  ((QueryData*)results)->push_back(r);
}

QueryData genACPITables(QueryContext& context) {
  QueryData results;

  auto matching = IOServiceMatching(kIOACPIClassName_);
  if (matching == nullptr) {
    // No ACPI platform expert service found.
    return {};
  }

  auto service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
  if (service == 0) {
    return {};
  }

  CFTypeRef table = IORegistryEntryCreateCFProperty(
      service, CFSTR(kIOACPIPropertyName_), kCFAllocatorDefault, 0);
  if (table == nullptr) {
    IOObjectRelease(service);
    return {};
  }

  CFDictionaryApplyFunction((CFDictionaryRef)table, genACPITable, &results);

  CFRelease(table);
  IOObjectRelease(service);
  return results;
}
}
}
