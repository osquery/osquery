/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <sstream>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/info/firmware.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {
namespace {

const std::vector<std::string> kFormFactors = {
    "Unknown",     "Other", "SIP",  "DIP",  "ZIP",   "SOJ",
    "Proprietary", "SIMM",  "DIMM", "TSOP", "PGA",   "RIMM",
    "SODIMM",      "SRIMM", "SMD",  "SSMP", "QFP",   "TQFP",
    "SOIC",        "LCC",   "PLCC", "BGA",  "FPBGA", "LGA",
};

std::string getFormFactor(long id) {
  if (id < kFormFactors.size()) {
    return kFormFactors[id];
  }
  return std::to_string(id);
}

const std::vector<std::string> kMemoryTypes = {
    "Unknown",    "Other",  "DRAM",         "Synchronous DRAM",
    "CACHE DRAM", "EDO",    "EDRAM",        "VRAM",
    "SRAM",       "RAM",    "ROM",          "Flash",
    "EEPROM",     "FEPROM", "EPROM",        "CDRAM",
    "3DRAM",      "SDRAM",  "SGRAM",        "RDRAM",
    "DDR",        "DDR2",   "DDR2 FB-DIMM", "23",
    "DDR3",       "FBD2",   "DDR4"};

std::string getMemoryType(int id) {
  if (id < kMemoryTypes.size()) {
    return kMemoryTypes[id];
  }
  return std::to_string(id);
}

std::string getMemoryTypeDetails(int id) {
  switch (id) {
  case 1:
    return "Reserved";
  case 2:
    return "Other";
  case 4:
    return "Unknown";
  case 8:
    return "Fast-paged";
  case 16:
    return "Static column";
  case 32:
    return "Pseudo-static";
  case 64:
    return "RAMBUS";
  case 128:
    return "Synchronous";
  case 256:
    return "CMOS";
  case 512:
    return "EDO";
  case 1024:
    return "Window DRAM";
  case 2048:
    return "Cache DRAM";
  case 4096:
    return "Non-volatile";
  default:
    return std::to_string(id);
  }
}

uint32_t getMemorySize(const std::wstring& capacityWStr) {
  int base = 0; // Passing a base of 0 auto-detects the base.
  uint64_t capacityBytes = std::wcstoull(capacityWStr.data(), nullptr, base);
  // Capacity row from WMI is in bytes, convert to Megabytes which means the
  // column can remain an INTEGER.
  uint64_t size = capacityBytes / (1048576);
  if (size > UINT32_MAX) {
    LOG(ERROR) << "Physical memory overflows INTEGER column";
  }
  return uint32_t(size);
}

} // namespace

std::string to_iso8601_date(const FILETIME& ft) {
  SYSTEMTIME date = {0};

  if (FileTimeToSystemTime(&ft, &date) == FALSE) {
    return "";
  }

  std::ostringstream iso_date;
  iso_date << std::setfill('0');
  iso_date << std::setw(4) << date.wYear << "-" << std::setw(2) << date.wMonth
           << "-" << std::setw(2) << date.wDay;

  return iso_date.str();
}

QueryData genPlatformInfo(QueryContext& context) {
  QueryData results;

  std::string query =
      "select Manufacturer, SMBIOSBIOSVersion, ReleaseDate, "
      "SystemBiosMajorVersion, SystemBiosMinorVersion from Win32_BIOS";
  const auto request = WmiRequest::CreateWmiRequest(query);
  if (!request || !request->getStatus().ok()) {
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = request->results();
  if (wmiResults.size() != 1) {
    return results;
  }
  Row r;
  std::string sPlaceholder;
  wmiResults[0].GetString("Manufacturer", r["vendor"]);
  wmiResults[0].GetString("SMBIOSBIOSVersion", r["version"]);
  unsigned char majorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMajorVersion", majorRevision);
  unsigned char minorRevision = 0x0;
  wmiResults[0].GetUChar("SystemBiosMinorVersion", minorRevision);
  r["revision"] =
      std::to_string(majorRevision) + "." + std::to_string(minorRevision);

  FILETIME release_date = {0};
  wmiResults[0].GetDateTime("ReleaseDate", false, release_date);

  auto s = to_iso8601_date(release_date);
  r["date"] = s.empty() ? "-1" : s;

  auto opt_firmware_kind = getFirmwareKind();
  if (opt_firmware_kind.has_value()) {
    const auto& firmware_kind = opt_firmware_kind.value();
    r["firmware_type"] = getFirmwareKindDescription(firmware_kind);

  } else {
    LOG(ERROR) << "platform_info: Failed to determine the firmware type";
    r["firmware_type"] = "unknown";
  }

  results.push_back(r);
  return results;
}

QueryData genMemoryDevices(QueryContext& context) {
  QueryData results;

  const std::string query = "select * from Win32_PhysicalMemory";
  const auto request = WmiRequest::CreateWmiRequest(query);
  if (!request || !request->getStatus().ok()) {
    return results;
  }
  const std::vector<WmiResultItem>& wmiResults = request->results();
  if (wmiResults.size() <= 0) {
    return results;
  }
  for (int i = 0; i < wmiResults.size(); ++i) {
    Row r;
    long formFactorId;
    wmiResults[i].GetLong("FormFactor", formFactorId);
    r["form_factor"] = getFormFactor(formFactorId);
    long totalWidth = 0;
    wmiResults[i].GetLong("TotalWidth", totalWidth);
    r["total_width"] = INTEGER(totalWidth);
    long dataWidth = 0;
    wmiResults[i].GetLong("DataWidth", dataWidth);
    r["data_width"] = INTEGER(dataWidth);
    std::wstring capacityWStr;
    wmiResults[i].GetString(stringToWstring("Capacity"), capacityWStr);
    r["size"] = INTEGER(getMemorySize(capacityWStr));
    wmiResults[i].GetString("DeviceLocator", r["device_locator"]);
    wmiResults[i].GetString("BankLabel", r["bank_locator"]);
    long memoryType = 0;
    wmiResults[i].GetLong("MemoryType", memoryType);
    r["memory_type"] = getMemoryType(memoryType);
    long memoryTypeDetails = 0;
    wmiResults[i].GetLong("TypeDetail", memoryTypeDetails);
    r["memory_type_details"] = getMemoryTypeDetails(memoryTypeDetails);
    long maxSpeed = 0;
    wmiResults[i].GetLong("Speed", maxSpeed);
    r["max_speed"] = INTEGER(maxSpeed);
    long clockSpeed = 0;
    wmiResults[i].GetLong("ConfiguredClockSpeed", clockSpeed);
    r["configured_clock_speed"] = INTEGER(clockSpeed);
    wmiResults[i].GetString("Manufacturer", r["manufacturer"]);
    wmiResults[i].GetString("SerialNumber", r["serial_number"]);
    wmiResults[i].GetString("Tag", r["asset_tag"]);
    wmiResults[i].GetString("PartNumber", r["part_number"]);
    long minVoltage = 0;
    wmiResults[i].GetLong("MinVoltage", minVoltage);
    r["min_voltage"] = INTEGER(minVoltage);
    long maxVoltage = 0;
    wmiResults[i].GetLong("MaxVoltage", maxVoltage);
    r["max_voltage"] = INTEGER(maxVoltage);
    long configuredVoltage = 0;
    wmiResults[i].GetLong("ConfiguredVoltage", configuredVoltage);
    r["configured_voltage"] = INTEGER(configuredVoltage);

    // Unable to find match for these from WMI.
    r["handle"] = "";
    r["array_handle"] = "";
    r["set"] = "";

    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
