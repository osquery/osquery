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

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {
namespace tables {

const auto kFreePtr = [](auto ptr) { free(ptr); };

const auto kCloseInfoSet = [](auto infoset) {
  SetupDiDestroyDeviceInfoList(infoset);
};

using device_infoset_t = std::unique_ptr<void, decltype(kCloseInfoSet)>;

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
                                   const std::string& device_name = "") {
  LOG(WARNING) << msg << " for device " << device_name
               << ", error code: " + std::to_string(code);
}

// Unify the image path as systemRoot can contain systemroot and/or system32
static inline std::string kNormalizeImage(std::string& path) {
  std::transform(path.begin(), path.end(), path.begin(), ::tolower);
  char sys_root[MAX_PATH] = {0};
  GetSystemDirectory(sys_root, MAX_PATH);
  return sys_root +
         boost::regex_replace(path, boost::regex("^.*?system32"), "");
}

device_infoset_t setupDevInfoSet(const DWORD flags) {
  device_infoset_t infoset(
      SetupDiGetClassDevs(nullptr, nullptr, nullptr, flags), kCloseInfoSet);
  if (infoset.get() == INVALID_HANDLE_VALUE) {
    infoset.reset(nullptr);
  }
  return infoset;
}

Status getDeviceList(const device_infoset_t& infoset,
                     std::vector<SP_DEVINFO_DATA>& rdevices) {
  SP_DEVINSTALL_PARAMS install_params;
  ZeroMemory(&install_params, sizeof(SP_DEVINSTALL_PARAMS));
  install_params.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
  install_params.FlagsEx |=
      DI_FLAGSEX_ALLOWEXCLUDEDDRVS | DI_FLAGSEX_INSTALLEDDRIVER;

  unsigned long i = 0;
  auto devices_left = TRUE;
  do {
    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    devices_left = SetupDiEnumDeviceInfo(infoset.get(), i, &devInfo);
    if (devices_left == TRUE) {
      // Set install params for subsequent driver enumerations for efficiency
      SetupDiSetDeviceInstallParams(infoset.get(), &devInfo, &install_params);
      rdevices.push_back(devInfo);
    }
    i++;
  } while (devices_left == TRUE);

  auto err = GetLastError();
  if (err != ERROR_NO_MORE_ITEMS) {
    rdevices.clear();
    return Status(GetLastError(), "Error enumerating installed devices");
  }
  return Status();
}

Status getDeviceProperty(const device_infoset_t& infoset,
                         SP_DEVINFO_DATA& device,
                         const DEVPROPKEY& prop,
                         std::string& result) {
  unsigned long buff_size = 0;
  DEVPROPTYPE dev_prop_type;
  auto ret = SetupDiGetDevicePropertyW(
      infoset.get(), &device, &prop, &dev_prop_type, nullptr, 0, &buff_size, 0);
  auto err = GetLastError();
  if (err == ERROR_NOT_FOUND) {
    return Status();
  }
  if (err != ERROR_INSUFFICIENT_BUFFER) {
    return Status(GetLastError(),
                  "Error getting buffer size for device property");
  }

  std::unique_ptr<BYTE, decltype(kFreePtr)> drv_buff(
      static_cast<PBYTE>(malloc(buff_size)), kFreePtr);
  if (drv_buff == nullptr) {
    return Status(1, "Failed to malloc for device property buffer");
  }

  ret = SetupDiGetDevicePropertyW(infoset.get(),
                                  &device,
                                  &prop,
                                  &dev_prop_type,
                                  drv_buff.get(),
                                  buff_size,
                                  nullptr,
                                  0);
  if (ret == FALSE) {
    return Status(GetLastError(), "Error getting device property");
  }

  if (dev_prop_type == DEVPROP_TYPE_UINT32) {
    result = std::to_string(*(PUINT32)drv_buff.get());
  } else if (dev_prop_type == DEVPROP_TYPE_INT32) {
    result = std::to_string(*(PINT32)drv_buff.get());
  } else if (dev_prop_type == DEVPROP_TYPE_STRING) {
    std::wstring name((PWCHAR)drv_buff.get());
    result = std::string(name.begin(), name.end());
  } else if (dev_prop_type == DEVPROP_TYPE_FILETIME) {
    result =
        std::to_string(osquery::filetimeToUnixtime(*(PFILETIME)drv_buff.get()));
  } else {
    return Status(
        1, "Unhandled device property type " + std::to_string(dev_prop_type));
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

  return kNormalizeImage(path);
}

Status genServiceKeyMap(
    std::map<std::string, std::string>& services_image_map) {
  // Attempt to get all of the services image paths in the default location
  SQL sql("SELECT key, data FROM registry WHERE path LIKE'" + kServiceKeyPath +
          "%\\ImagePath'");

  // Something went wrong
  if (sql.rows().empty()) {
    return Status::failure("Failed to retrieve services image path cache");
  }

  char sys_root[MAX_PATH] = {0};
  GetSystemDirectory(sys_root, MAX_PATH);
  for (auto& row : sql.rows()) {
    if (row.count("key") == 0 || row.count("data") == 0) {
      continue;
    }
    services_image_map[row.at("key")] = kNormalizeImage(row.at("data"));
  }
  return Status::success();
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  WmiRequest wmiSignedDriverReq("select * from Win32_PnPSignedDriver");
  auto& wmi_results = wmiSignedDriverReq.results();

  // As our list relies on the WMI set we first query and bail if no results
  if (wmi_results.empty()) {
    LOG(WARNING) << "Failed to query device drivers via WMI";
    return {};
  }

  auto dev_info_set = setupDevInfoSet(DIGCF_ALLCLASSES | DIGCF_PRESENT);
  if (dev_info_set == nullptr) {
    win32LogWARNING("Error getting device handle");
    return results;
  }

  std::map<std::string, Row> api_devices;
  std::vector<SP_DEVINFO_DATA> devices;
  auto ret = getDeviceList(dev_info_set, devices);
  if (!ret.ok()) {
    win32LogWARNING(ret.getMessage(), ret.getCode());
    return results;
  }

  std::map<std::string, std::string> svc_image_map;
  auto s = genServiceKeyMap(svc_image_map);
  if (!s.ok()) {
    VLOG(1) << "Failed to construct service image path cache";
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
      ret = getDeviceProperty(dev_info_set, device, elem.second, val);
      r[elem.first] = std::move(val);
    }

    if (r.count("driver_key") > 0 && !r.at("driver_key").empty()) {
      r["driver_key"].insert(0, kDriverKeyPath);
    }

    if (r.count("service") > 0 && !r.at("service").empty()) {
      auto svc_key = kServiceKeyPath + r["service"];
      r["service_key"] = svc_key;

      // If the image map doesn't exist in the cache, manually look it up
      if (!svc_image_map.empty() &&
          svc_image_map.find(svc_key) != svc_image_map.end()) {
        r["image"] = svc_image_map[svc_key];
      } else {
        // Manual lookups of the service keys image path are _very_ slow
        VLOG(1) << r["service"]
                << " not found in image cache, performing manual lookup";
        r["image"] = getDriverImagePath(svc_key);
      }
    }
    api_devices[devId] = r;
  }

  /*
   * We balance getting information from WMI and Win32 APIs as not
   * all data is available in only one place. Unfortunately this means
   * two runs through the devices list, but this takes less time
   * than the Win32 API method
   */
  for (const auto& row : wmi_results) {
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

    bool is_signed;
    row.GetBool("IsSigned", is_signed);
    r["signed"] = is_signed ? INTEGER(1) : INTEGER(0);

    std::string inf_name;
    row.GetString("InfName", inf_name);
    std::vector<char> inf(MAX_PATH, 0x0);
    unsigned long infLen = 0;
    auto sdiRet =
        SetupGetInfDriverStoreLocation(inf_name.c_str(),
                                       nullptr,
                                       nullptr,
                                       inf.data(),
                                       static_cast<unsigned long>(inf.size()),
                                       &infLen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      inf.resize(infLen);
      sdiRet =
          SetupGetInfDriverStoreLocation(inf_name.c_str(),
                                         nullptr,
                                         nullptr,
                                         inf.data(),
                                         static_cast<unsigned long>(inf.size()),
                                         &infLen);
    }
    if (sdiRet != TRUE) {
      VLOG(1) << "Failed to derive full driver INF path for "
              << r["device_name"] << " with " << GetLastError();
      r["inf"] = inf_name;
    } else {
      r["inf"] = inf.data();
    }

    // Add the remaining columns from the APIs
    auto dev = api_devices.find(devid);
    if (dev != api_devices.end()) {
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
