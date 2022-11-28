/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mach/mach.h>
#include <sys/sysctl.h>

#include <IOKit/IOKitLib.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <boost/algorithm/string.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

/**
 * Get a string from a sysctl name.
 *
 * @param name sysctl property name
 */
std::string getSysctlString(const std::string& name) {
  size_t len = 0;
  std::string ret;

  sysctlbyname(name.c_str(), NULL, &len, NULL, 0);

  if (len > 0) {
    char* value = (char*)malloc(len);
    if (!sysctlbyname(name.c_str(), value, &len, NULL, 0)) {
      ret = value;
    }

    free(value);
  }

  return ret;
}

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
  r["hardware_model"] = getIOKitProperty(properties, "model");
  r["hardware_serial"] = getIOKitProperty(properties, "IOPlatformSerialNumber");

  // version, manufacturer, and product-name have a trailing space
  boost::trim(r["hardware_version"]);
  boost::trim(r["hardware_vendor"]);
  boost::trim(r["hardware_model"]);
  boost::trim(r["hardware_serial"]);

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

  // The CPU brand string.
  r["cpu_brand"] = getSysctlString("machdep.cpu.brand_string");
  boost::trim(r["cpu_brand"]);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
