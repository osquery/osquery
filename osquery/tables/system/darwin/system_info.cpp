/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mach/mach.h>

#include <IOKit/IOKitLib.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <boost/algorithm/string.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/events/darwin/iokit.h"

#define DECLARE_TABLE_IMPLEMENTATION_system_info
#include <generated/tables/tbl_system_info_defs.hpp>

namespace osquery {
namespace tables {

static inline void genHostInfo(Row& r) {
  auto host = mach_host_self();

  host_basic_info_data_t host_data;
  mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
  if (host_info(host, HOST_BASIC_INFO, (host_info_t)&host_data, &count) !=
      KERN_SUCCESS) {
    return;
  }

  char* cpu_type = nullptr;
  char* cpu_subtype = nullptr;
  // Get human readable strings
  slot_name(host_data.cpu_type, host_data.cpu_subtype, &cpu_type, &cpu_subtype);

  r["cpu_type"] = (cpu_type != nullptr) ? std::string(cpu_type) : "";
  r["cpu_subtype"] = (cpu_subtype != nullptr) ? std::string(cpu_subtype) : "";

  r["cpu_physical_cores"] = INTEGER(host_data.physical_cpu_max);
  r["cpu_logical_cores"] = INTEGER(host_data.logical_cpu_max);
  r["physical_memory"] = BIGINT(host_data.max_mem);
}

static inline void genHardwareInfo(Row& r) {
  auto root = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/");
  if (root == MACH_PORT_NULL) {
    VLOG(1) << "Cannot get hardware information from IOKit";
    return;
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      root, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(root);

  if (kr != KERN_SUCCESS) {
    VLOG(1) << "Cannot get hardware properties from IOKit";
    return;
  }

  r["hardware_version"] = getIOKitProperty(properties, "version");
  r["hardware_vendor"] = getIOKitProperty(properties, "manufacturer");
  r["hardware_model"] = getIOKitProperty(properties, "product-name");
  r["hardware_serial"] = getIOKitProperty(properties, "IOPlatformSerialNumber");
  CFRelease(properties);
}

QueryData genSystemInfo(QueryContext& context) {
  QueryData results;
  Row r;

  // OS X also defines a friendly ComputerName along with a hostname.
  r["hostname"] = osquery::getFqdn();
  auto cn = SCDynamicStoreCopyComputerName(nullptr, nullptr);
  if (cn != nullptr) {
    r["computer_name"] = stringFromCFString(cn);
    CFRelease(cn);
  } else {
    r["computer_name"] = getHostname();
  }

  auto lhn = SCDynamicStoreCopyLocalHostName(nullptr);
  if (lhn != nullptr) {
    r["local_hostname"] = stringFromCFString(lhn);
    CFRelease(lhn);
  } else {
    r["local_hostname"] = getHostname();
  }

  // The UUID for Apple devices is a device identifier.
  std::string uuid;
  r["uuid"] = (osquery::getHostUUID(uuid)) ? uuid : "";

  genHostInfo(r);
  genHardwareInfo(r);

  // The CPU brand string also exists in system_controls.
  auto qd = SQL::selectAllFrom("cpuid");
  for (const auto& row : qd) {
    if (row.at("feature") == "product_name") {
      r["cpu_brand"] = row.at("value");
      boost::trim(r["cpu_brand"]);
    }
  }

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
