/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/database.h>
#include <osquery/tables.h>
#include "osquery/core/conversions.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

namespace osquery {
namespace tables {

Status getCpuSerial(std::string& cpu_serial) {
  static std::string serial_cache;
  if (!serial_cache.empty()) {
    cpu_serial = serial_cache;
    return Status(0, "OK");
  }

  auto matching = IOServiceMatching("IOPlatformExpertDevice");
  if (matching == nullptr) {
    return Status(1, "Could not get service matching IOPlatformExpertDevice");
  }

  io_iterator_t it;
  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return Status(1, "Could not get iterator");
  }

  // There should be only one service, so just grab the first one
  io_service_t service;
  service = IOIteratorNext(it);
  if (service == 0) {
    return Status(1, "Could not iterate to get service");
  }

  CFStringRef serialNumber = (CFStringRef)IORegistryEntryCreateCFProperty(
    service,
    CFSTR("IOPlatformSerialNumber"),
    kCFAllocatorDefault,
    kNilOptions);
  IOObjectRelease(service);
  if (serialNumber == nullptr) {
    return Status(1, "Could not read serial number property");
  }

  cpu_serial = serial_cache = stringFromCFString(serialNumber);
  CFRelease(serialNumber);
  if (cpu_serial.empty()) {
    return Status(1, "cpu_serial was empty");
  }

  return Status(0, "OK");
}

QueryData genSystemInfo(QueryContext& context) {

  Row r;
  r["hostname"] = TEXT(osquery::getHostname());

  std::string uuid;
  auto status = osquery::getHostUUID(uuid);
  if (!status.ok()) {
    uuid = "";
  }
  r["uuid"] = TEXT(uuid);

  std::string cpu_serial;
  status = getCpuSerial(cpu_serial);
  if (!status.ok()) {
    cpu_serial = "";
  }
  r["cpu_serial"] = TEXT(cpu_serial);

  return {r};
}
}
}
