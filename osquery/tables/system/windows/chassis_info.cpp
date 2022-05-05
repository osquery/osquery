/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genChassisInfo(QueryContext& context) {
  QueryData results;

  Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_SystemEnclosure");

  // check if the results are empty and return a warning if so
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();

  // DSP0134: System Management BIOS (SMBIOS) Reference Specification
  // Section: Enclosure/chassis types.
  // Published: August 20, 2020
  // https://www.dmtf.org/standards/smbios
  const std::map<long, std::string> enclosureTypes = {
      {0x01, "Other"},
      {0x02, "Unknown"},
      {0x03, "Desktop"},
      {0x04, "Low Profile Desktop"},
      {0x05, "Pizza Box"},
      {0x06, "Mini Tower"},
      {0x07, "Tower"},
      {0x08, "Portable"},
      {0x09, "Laptop"},
      {0x0A, "Notebook"},
      {0x0B, "Hand Held"},
      {0x0C, "Docking Station"},
      {0x0D, "All in One"},
      {0x0E, "Sub Notebook"},
      {0x0F, "Space-saving"},
      {0x10, "Lunch Box"},
      {0x11, "Main Server Chassis"},
      {0x12, "Expansion Chassis"},
      {0x13, "SubChassis"},
      {0x14, "Bus Expansion Chassis"},
      {0x15, "Peripheral Chassis"},
      {0x16, "RAID Chassis"},
      {0x17, "Rack Mount Chassis"},
      {0x18, "Sealed-case PC"},
      {0x19, "Multi-system chassis"},
      {0x1A, "Compact PCI"},
      {0x1B, "Advanced TCA"},
      {0x1C, "Blade"},
      {0x1D, "Blade Enclosure"},
      {0x1E, "Tablet"},
      {0x1F, "Convertible"},
      {0x20, "Detachable"},
      {0x21, "IoT Gateway"},
      {0x22, "Embedded PC"},
      {0x23, "Mini PC"},
      {0x24, "Stick PC"}};

  for (const auto& data : wmiResults) {
    Row r;
    auto isPresent = false;
    unsigned short number;
    std::vector<long> chassisTypes;
    data.GetBool("AudibleAlarm", isPresent);
    r["audible_alarm"] = isPresent ? "True" : "False";
    data.GetString("BreachDescription", r["breach_description"]);
    data.GetVectorOfLongs("ChassisTypes", chassisTypes);

    std::ostringstream oValueConcat;
    for (size_t i = 0; i < chassisTypes.size(); ++i) {
      if (i != 0) {
        oValueConcat << ',';
      }
      auto chassisType = enclosureTypes.find(chassisTypes[i]);
      if (chassisType == enclosureTypes.end()) {
        oValueConcat << "Unknown (" << chassisTypes[i] << ")";
      } else {
        oValueConcat << chassisType->second;
      }
    }

    r["chassis_types"] = SQL_TEXT(oValueConcat.str());
    data.GetString("Description", r["description"]);

    // reset boolean to make sure there is no interference from the last call
    isPresent = false;

    data.GetBool("LockPresent", isPresent);
    r["lock"] = isPresent ? "True" : "False";
    data.GetString("Manufacturer", r["manufacturer"]);
    data.GetString("Model", r["model"]);

    const std::map<unsigned short, std::string> securityBreachStatus = {
        {1, "Other"},
        {2, "Unknown"},
        {3, "No Breach"},
        {4, "Breach Attempted"},
        {5, "Breach Successful"},
    };

    if (!data.GetUnsignedShort("SecurityBreach", number).ok()) {
      number = 2; // unknown
    }

    const auto breachCode = securityBreachStatus.find(number);
    r["security_breach"] = breachCode != securityBreachStatus.end()
                               ? SQL_TEXT(breachCode->second)
                               : SQL_TEXT(std::to_string(number));

    data.GetString("SerialNumber", r["serial"]);
    data.GetString("SMBIOSAssetTag", r["smbios_tag"]);
    data.GetString("SKU", r["sku"]);
    data.GetString("Status", r["status"]);

    // reset boolean to make sure there is no interference from the last call
    isPresent = false;

    data.GetBool("VisibleAlarm", isPresent);
    r["visible_alarm"] = isPresent ? "True" : "False";
    results.push_back(std::move(r));
  }

  return results;
}

} // namespace tables
} // namespace osquery
