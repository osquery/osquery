/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

// clang-format off
#include <Windows.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <Devpkey.h>
#include <cfgmgr32.h>
// clang-format on

#include <boost/regex.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"

#define DECLARE_TABLE_IMPLEMENTATION_drivers
#include <generated/tables/tbl_drivers_defs.hpp>

namespace osquery {
namespace tables {

const auto freePtr = [](auto ptr) { free(ptr); };

const auto closeInfoSet = [](auto infoset) {
  SetupDiDestroyDeviceInfoList(infoset);
};

using device_infoset_t = std::unique_ptr<void, decltype(closeInfoSet)>;

const std::map<std::string, DEVPROPKEY> kAdditionalDeviceProps = {
    {"service", DEVPKEY_Device_Service},
    {"driver_key", DEVPKEY_Device_Driver},
    {"date", DEVPKEY_Device_DriverDate}};
const std::string kDriverKeyPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\";
const std::string kServiceKeyPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\";

static inline void win32LogWARNING(const std::string& msg,
                                   const DWORD code = GetLastError(),
                                   const std::string& deviceName = "") {
  LOG(WARNING) << msg << " for device " << deviceName
               << ", error code: " + std::to_string(code);
}

device_infoset_t setupDevInfoSet(const DWORD flags) {
  device_infoset_t infoset(
      SetupDiGetClassDevs(nullptr, nullptr, nullptr, flags), closeInfoSet);
  if (infoset.get() == INVALID_HANDLE_VALUE) {
    infoset.reset(nullptr);
  }
  return infoset;
}

Status getDeviceList(const device_infoset_t& infoset,
                     std::vector<SP_DEVINFO_DATA>& rDevices) {
  SP_DEVINSTALL_PARAMS installParams;
  ZeroMemory(&installParams, sizeof(SP_DEVINSTALL_PARAMS));
  installParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
  installParams.FlagsEx |=
      DI_FLAGSEX_ALLOWEXCLUDEDDRVS | DI_FLAGSEX_INSTALLEDDRIVER;

  DWORD i = 0;
  BOOL devicesLeft = TRUE;
  do {
    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    devicesLeft = SetupDiEnumDeviceInfo(infoset.get(), i, &devInfo);
    if (devicesLeft == TRUE) {
      // Set install params to make any subsequent driver enumerations on this
      // device more efficient
      SetupDiSetDeviceInstallParams(infoset.get(), &devInfo, &installParams);
      rDevices.push_back(devInfo);
    }
    i++;
  } while (devicesLeft == TRUE);

  auto err = GetLastError();
  if (err != ERROR_NO_MORE_ITEMS) {
    rDevices.clear();
    return Status(GetLastError(), "Error enumerating installed devices");
  }
  return Status();
}

Status getDeviceProperty(const device_infoset_t& infoset,
                         SP_DEVINFO_DATA& device,
                         const DEVPROPKEY& prop,
                         std::string& result) {
  DWORD buffSize;
  DEVPROPTYPE devPropType;
  auto ret = SetupDiGetDevicePropertyW(
      infoset.get(), &device, &prop, &devPropType, nullptr, 0, &buffSize, 0);
  auto err = GetLastError();
  if (err == ERROR_NOT_FOUND) {
    return Status();
  }
  if (err != ERROR_INSUFFICIENT_BUFFER) {
    return Status(GetLastError(),
                  "Error getting buffer size for device property");
  }

  std::unique_ptr<BYTE, decltype(freePtr)> drvBuff(
      static_cast<PBYTE>(malloc(buffSize)), freePtr);
  if (drvBuff == nullptr) {
    return Status(1, "Failed to malloc for device property buffer");
  }

  ret = SetupDiGetDevicePropertyW(infoset.get(),
                                  &device,
                                  &prop,
                                  &devPropType,
                                  drvBuff.get(),
                                  buffSize,
                                  nullptr,
                                  0);
  if (ret == FALSE) {
    return Status(GetLastError(), "Error getting device property");
  }

  if (devPropType == DEVPROP_TYPE_UINT32) {
    result = std::to_string(*(PUINT32)drvBuff.get());
  } else if (devPropType == DEVPROP_TYPE_INT32) {
    result = std::to_string(*(PINT32)drvBuff.get());
  } else if (devPropType == DEVPROP_TYPE_STRING) {
    std::wstring name((PWCHAR)drvBuff.get());
    result = std::string(name.begin(), name.end());
  } else if (devPropType == DEVPROP_TYPE_FILETIME) {
    result =
        std::to_string(osquery::filetimeToUnixtime(*(PFILETIME)drvBuff.get()));
  } else {
    return Status(
        1, "Unhandled device property type " + std::to_string(devPropType));
  }

  return Status();
}

std::string getDriverImagePath(const std::string& service_key) {
  SQL sql("SELECT data FROM registry WHERE path = '" + service_key +
          "\\ImagePath'");

  if (sql.rows().empty() || sql.rows().at(0).count("data") == 0) {
    return "";
  }

  auto path = sql.rows().at(0).at("data");
  if (path.empty()) {
    return "";
  }

  // Unify the image path as systemRoot can contain systemroot and/or system32
  std::transform(path.begin(), path.end(), path.begin(), ::tolower);

  char systemRoot[MAX_PATH] = {0};
  GetSystemDirectory(systemRoot, MAX_PATH);

  return systemRoot +
         boost::regex_replace(path, boost::regex("^.*?system32"), "");
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  WmiRequest wmiSignedDriverReq("select * from Win32_PnPSignedDriver");
  auto& wmiResults = wmiSignedDriverReq.results();

  // As our list relies on the WMI set we first query and bail if no results
  if (wmiResults.empty()) {
    LOG(WARNING) << "Failed to query device drivers via WMI";
    return {};
  }

  auto devInfoset = setupDevInfoSet(DIGCF_ALLCLASSES | DIGCF_PRESENT);
  if (devInfoset == nullptr) {
    win32LogWARNING("Error getting device handle");
    return results;
  }

  std::map<std::string, Row> apiDevices;
  std::vector<SP_DEVINFO_DATA> devices;
  auto ret = getDeviceList(devInfoset, devices);
  if (!ret.ok()) {
    win32LogWARNING(ret.getMessage(), ret.getCode());
    return results;
  }

  // Then, leverage the Windows APIs to get whatever remains
  for (auto& device : devices) {
    char devId[MAX_DEVICE_ID_LEN] = {0};
    if (CM_Get_Device_ID(device.DevInst, devId, MAX_DEVICE_ID_LEN, 0) !=
        CR_SUCCESS) {
      win32LogWARNING("Failed to get device ID");
      continue;
    }

    Row r;
    for (const auto& elem : kAdditionalDeviceProps) {
      std::string val;
      ret = getDeviceProperty(devInfoset, device, elem.second, val);
      r[elem.first] = std::move(val);
    }

    if (r.count("driver_key") > 0 && !r.at("driver_key").empty()) {
      r["driver_key"].insert(0, kDriverKeyPath);
    }

    if (r.count("service") > 0 && !r.at("service").empty()) {
      auto svcKey = kServiceKeyPath + r["service"];
      r["service_key"] = svcKey;
      r["image"] = getDriverImagePath(svcKey);
    }
    apiDevices[devId] = r;
  }

  /*
   * We balance getting information from WMI and Win32 APIs as not
   * all data is available in only one place. Unfortunately this means
   * two runs through the devices list, but this takes less time
   * than the Win32 API method
   */
  for (const auto& row : wmiResults) {
    Row r;
    std::string devid;
    row.GetString("DeviceID", devid);
    r["device_id"] = devid;
    row.GetString("DeviceName", r["device_name"]);
    row.GetString("Description", r["description"]);
    row.GetString("DeviceClass", r["class"]);
    row.GetString("DriverVersion", r["version"]);
    row.GetString("Manufacturer", r["manufacturer"]);
    row.GetString("DriverProviderName", r["provider"]);

    bool isSigned;
    row.GetBool("IsSigned", isSigned);
    r["signed"] = isSigned ? INTEGER(1) : INTEGER(0);

    std::string infName;
    row.GetString("InfName", infName);
    std::vector<char> inf(MAX_PATH, 0x0);
    unsigned long infLen = 0;
    auto sdiRet =
        SetupGetInfDriverStoreLocation(infName.c_str(),
                                       nullptr,
                                       nullptr,
                                       inf.data(),
                                       static_cast<unsigned long>(inf.size()),
                                       &infLen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      inf.resize(infLen);
      sdiRet =
          SetupGetInfDriverStoreLocation(infName.c_str(),
                                         nullptr,
                                         nullptr,
                                         inf.data(),
                                         static_cast<unsigned long>(inf.size()),
                                         &infLen);
    }
    if (sdiRet != TRUE) {
      VLOG(1) << "Failed to derive full driver INF path for "
              << r["device_name"] << " with " << GetLastError();
      r["inf"] = infName;
    } else {
      r["inf"] = inf.data();
    }

    // Add the remaining columns from the APIs
    auto dev = apiDevices.find(devid);
    if (dev != apiDevices.end()) {
      r["service"] = dev->second["service"];
      r["service_key"] = dev->second["service_key"];
      r["image"] = dev->second["image"];
      r["driver_key"] = dev->second["driver_key"];
      r["date"] = dev->second["date"];
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
