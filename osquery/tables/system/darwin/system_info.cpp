/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mach/mach.h>

#include <IOKit/IOKitLib.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <boost/algorithm/string.hpp>

#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/darwin/smbios_utils.h"

namespace osquery {
namespace tables {

const std::string kMachCpuBrandStringKey = "machdep.cpu.brand_string";
const std::string kHardwareModelNameKey = "hw.model";

void genHostInfo(Row &r) {
  auto host = mach_host_self();
  host_basic_info_data_t host_data;
  mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

  if (host_info(host, HOST_BASIC_INFO, (host_info_t)&host_data, &count) !=
      KERN_SUCCESS) {
    return;
  }

  char *cpu_type = nullptr;
  char *cpu_subtype = nullptr;
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

  // OS X also defines a friendly ComputerName along with a hostname.
  r["hostname"] = osquery::getHostname();
  auto cn = SCDynamicStoreCopyComputerName(nullptr, nullptr);
  if (cn != nullptr) {
    r["computer_name"] = stringFromCFString(cn);
    CFRelease(cn);
  } else {
    r["computer_name"] = r["hostname"];
  }

  auto lhn = SCDynamicStoreCopyLocalHostName(nullptr);
  if (lhn != nullptr) {
    r["local_host_name"] = stringFromCFString(lhn);
    CFRelease(lhn);
  } else {
    r["local_host_name"] = r["hostname"];
  }

  // The UUID for Apple devices is a device identifier.
  std::string uuid;
  r["uuid"] = (osquery::getHostUUID(uuid)) ? uuid : "";

  genHostInfo(r);

  // The CPU brand string also exists in system_controls.
  auto qd = SQL::selectAllFrom("cpuid");
  for (const auto &row : qd) {
    if (row.at("feature") == "product_name") {
      r["cpu_brand"] = row.at("value");
      boost::trim(r["cpu_brand"]);
    }
  }

  {
    DarwinSMBIOSParser parser;
    if (!parser.discover()) {
      r["hardware_model"] = "";
      r["hardware_vendor"] = "";
      r["hardware_version"] = "";
      r["hardware_serial"] = "";
    } else {
      parser.tables(([&r](size_t index,
                          const SMBStructHeader *hdr,
                          uint8_t *address,
                          size_t size) {
        if (hdr->type != kSMBIOSTypeSystem || size < 0x12) {
          return;
        }

        uint8_t *data = address + hdr->length;
        r["hardware_vendor"] = dmiString(data, address, 0x04);
        r["hardware_model"] = dmiString(data, address, 0x05);
        r["hardware_version"] = dmiString(data, address, 0x06);
        r["hardware_serial"] = dmiString(data, address, 0x07);
      }));
    }
  }

  results.push_back(r);
  return results;
}
}
}
