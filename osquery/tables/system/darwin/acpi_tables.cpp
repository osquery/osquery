/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <osquery/core/tables.h>
#include <osquery/hashing/hashing.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

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
