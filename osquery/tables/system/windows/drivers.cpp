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

#include <Windows.h>
#include <initguid.h>

#include <Devpkey.h>
#include <cfgmgr32.h>

#include <boost/regex.hpp>

#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/drivers.h"

#define DECLARE_TABLE_IMPLEMENTATION_drivers
#include <generated/tables/tbl_drivers_defs.hpp>

namespace osquery {
namespace tables {

const auto freePtr = [](auto ptr) { free(ptr); };

const std::map<std::string, DEVPROPKEY> kAdditionalDeviceProps = {
    {"device_name", DEVPKEY_NAME},
    {"service", DEVPKEY_Device_Service},
    {"driver_key", DEVPKEY_Device_Driver},
    {"class", DEVPKEY_Device_Class}};
const std::string kDriverKeyPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\";
const std::string kServiceKeyPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\";

static inline void win32LogWARNING(const std::string& msg,
                                   const DWORD code = GetLastError()) {
  LOG(WARNING) << msg + " Error code: " + std::to_string(code);
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

Status getDeviceDriverInfo(const device_infoset_t& infoset,
                           SP_DEVINFO_DATA& device,
                           SP_DRVINFO_DATA& rDriverInfo,
                           SP_DRVINFO_DETAIL_DATA& rDriverInfoDetail) {
  rDriverInfo.cbSize = sizeof(SP_DRVINFO_DATA);
  rDriverInfoDetail.cbSize = sizeof(SP_DRVINFO_DETAIL_DATA);

  auto ret =
      SetupDiBuildDriverInfoList(infoset.get(), &device, SPDIT_CLASSDRIVER);
  if (ret == FALSE) {
    return Status(GetLastError(), "Error building driver info list");
  }

  ret = SetupDiEnumDriverInfo(
      infoset.get(), &device, SPDIT_CLASSDRIVER, 0, &rDriverInfo);
  if (ret == FALSE) {
    return Status(GetLastError(), "Error enumerating driver info");
  }

  ret = SetupDiGetDriverInfoDetail(infoset.get(),
                                   &device,
                                   &rDriverInfo,
                                   &rDriverInfoDetail,
                                   sizeof(SP_DRVINFO_DETAIL_DATA),
                                   nullptr);
  if (ret == FALSE) {
    auto err = GetLastError();
    // It's common to get INSUFFICIENT_BUFFER for some variable length fields in
    // SP_DRVINFO_DETAIL_DATA, but we don't care about this info so ignore it
    if (err != ERROR_INSUFFICIENT_BUFFER) {
      return Status(err, "Error getting detailed driver info");
    }
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

static inline std::string getDriverImagePath(const std::string& service_key) {
  SQL sql("SELECT data FROM registry WHERE path = '" + service_key +
          "\\ImagePath'");
  if (sql.rows().size() == 1) {
    auto path = sql.rows().at(0).at("data");
    if (!path.empty()) {
      CHAR systemRoot[MAX_PATH] = {0};
      GetSystemDirectory(systemRoot, MAX_PATH);
      return systemRoot +
             boost::regex_replace(path, boost::regex("^.*[Ss]ystem32"), "");
    }
  }
  return "";
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  auto devInfoset = setupDevInfoSet();
  if (devInfoset == nullptr) {
    win32LogWARNING("Error getting device handle");
    return results;
  }

  std::vector<SP_DEVINFO_DATA> devices;
  auto ret = getDeviceList(devInfoset, devices);
  if (!ret.ok()) {
    win32LogWARNING(ret.getMessage(), ret.getCode());
    return results;
  }

  for (auto& device : devices) {
    char devId[MAX_DEVICE_ID_LEN] = {0};
    if (CM_Get_Device_ID(device.DevInst, devId, MAX_DEVICE_ID_LEN, 0) !=
        CR_SUCCESS) {
      win32LogWARNING("Failed to get device ID");
      return QueryData();
    }

    SP_DRVINFO_DATA drvInfo = {0};
    SP_DRVINFO_DETAIL_DATA drvInfoDetail = {0};
    ret = getDeviceDriverInfo(devInfoset, device, drvInfo, drvInfoDetail);

    Row r;
    r["device_id"] = devId;
    r["inf"] = drvInfoDetail.InfFileName;
    r["provider"] = drvInfo.ProviderName;
    r["manufacturer"] = drvInfo.MfgName;
    r["date"] = std::to_string(osquery::filetimeToUnixtime(drvInfo.DriverDate));
    r["description"] = drvInfo.Description;
    ULARGE_INTEGER version;
    version.QuadPart = drvInfo.DriverVersion;
    r["version"] = std::to_string(HIWORD(version.HighPart)) + "." +
                   std::to_string(HIWORD(version.LowPart)) + "." +
                   std::to_string(LOWORD(version.HighPart)) + "." +
                   std::to_string(LOWORD(version.LowPart));

    for (const auto& elem : kAdditionalDeviceProps) {
      std::string val;
      ret = getDeviceProperty(devInfoset, device, elem.second, val);
      r[elem.first] = std::move(val);
    }

    if (r.count("driver_key") > 0) {
      if (!r.at("driver_key").empty()) {
        r["driver_key"].insert(0, kDriverKeyPath);
      }
    }
    if (r.count("service") > 0) {
      if (!r.at("service").empty()) {
        r["service_key"] = kServiceKeyPath + r["service"];
        r["image"] = getDriverImagePath(r["service_key"]);
      }
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
