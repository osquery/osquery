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
#include <SystemConfiguration/SystemConfiguration.h>

#include <mach/mach.h>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/sysctl_utils.h"

#define kIOPlatformClassName_ "IOPlatformExpertDevice"

namespace osquery {
namespace tables {

const std::string kMachCpuBrandStringKey = "machdep.cpu.brand_string";
const std::string kHardwareModelNameKey = "hw.model";

Status getHardwareSerial(std::string &serial) {
  static std::string serial_cache;
  if (!serial_cache.empty()) {
    serial = serial_cache;
    return Status(0, "OK");
  }

  auto matching = IOServiceMatching(kIOPlatformClassName_);
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

  serial = serial_cache = stringFromCFString(serialNumber);
  CFRelease(serialNumber);
  return Status(0, "OK");
}

void genHostInfo(Row &r) {
  auto host = mach_host_self();
  host_basic_info_data_t host_data;
  mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

  if (host_info(host, HOST_BASIC_INFO, (host_info_t)&host_data, &count) !=
      KERN_SUCCESS) {
    return;
  }

  char *cpu_type;
  char *cpu_subtype;
  // Get human readable strings
  slot_name(host_data.cpu_type, host_data.cpu_subtype, &cpu_type, &cpu_subtype);

  r["cpu_type"] = (cpu_type != nullptr) ? std::string(cpu_type) : "";
  r["cpu_subtype"] = (cpu_subtype != nullptr) ? std::string(cpu_subtype) : "";

  r["cpu_physical_cores"] = INTEGER(host_data.physical_cpu_max);
  r["cpu_logical_cores"] = INTEGER(host_data.logical_cpu_max);
  r["physical_memory"] = BIGINT(host_data.max_mem);
}

QueryData genSystemInfo(QueryContext &context) {
  QueryData results;
  Row r;
  r["hostname"] = osquery::getHostname();

  // OS X also defines a friendly ComputerName.
  auto cn = SCDynamicStoreCopyComputerName(nullptr, nullptr);
  if (cn != nullptr) {
    r["computer_name"] = stringFromCFString(cn);
    CFRelease(cn);
  } else {
    r["computer_name"] = r["hostname"];
  }

  std::string uuid;
  r["uuid"] = (osquery::getHostUUID(uuid)) ? uuid : "";
  std::string serial;
  r["hardware_serial"] = (getHardwareSerial(serial)) ? serial : "";
  genHostInfo(r);

  QueryData sysctl_results;
  // Empty config since we don't want to read sysctl.conf files
  std::map<std::string, std::string> config;
  genControlInfoFromName(kMachCpuBrandStringKey, sysctl_results, config);
  genControlInfoFromName(kHardwareModelNameKey, sysctl_results, config);

  if (!sysctl_results.empty()) {
    // If genControlInfoForName() for cpu_brand and hw_model succeeds,
    // there should be exactly two elements in sysctl_results
    const auto &cpu_brand = sysctl_results.front();
    const auto &hw_model = sysctl_results.back();

    if (cpu_brand.count("name") > 0 &&
        cpu_brand.at("name") == kMachCpuBrandStringKey) {
      r["cpu_brand"] = cpu_brand.at("current_value");
    }

    if (hw_model.count("name") > 0 &&
        hw_model.at("name") == kHardwareModelNameKey) {
      r["hardware_model"] = hw_model.at("current_value");
    }
  }

  results.push_back(r);
  return results;
}
}
}
