/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

// clang-format off
#include <osquery/utils/system/system.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <Devpkey.h>
#include <cfgmgr32.h>
// clang-format on

#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/tables/system/windows/registry.h>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/regex.hpp>

namespace osquery {
namespace tables {

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
  boost::algorithm::to_lower(path);

  std::wstring sys_root(MAX_PATH, L'\0');
  auto ret = GetSystemDirectory(&sys_root.front(),
                                static_cast<unsigned int>(sys_root.size()));
  if (ret == 0) {
    VLOG(1) << "Failed to get the system directory with " << GetLastError();
    return "";
  }
  if (ret > sys_root.size()) {
    sys_root.resize(ret);
    ret = GetSystemDirectory(&sys_root.front(),
                             static_cast<unsigned int>(sys_root.size()));
  }
  if (path.find("system32") != std::string::npos) {
    boost::regex_replace(path, boost::regex("^.*?system32"), "");
  }
  return wstringToString(sys_root.append(stringToWstring(path)));
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
    return Status::failure("Failed to enumerate installed devices with " +
                           std::to_string(GetLastError()));
  }
  return Status::success();
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
    return Status::success();
  }
  if (err != ERROR_INSUFFICIENT_BUFFER) {
    return Status::failure(
        "Failed to get buffer size for device property with " +
        std::to_string(GetLastError()));
  }

  auto drv_buff = std::make_unique<BYTE[]>(buff_size);
  if (drv_buff == nullptr) {
    return Status::failure("Failed to malloc for device property buffer");
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
    return Status::failure("Failed to get device property with " +
                           std::to_string(GetLastError()));
  }

  if (dev_prop_type == DEVPROP_TYPE_UINT32) {
    result = std::to_string(*(PUINT32)drv_buff.get());
  } else if (dev_prop_type == DEVPROP_TYPE_INT32) {
    result = std::to_string(*(PINT32)drv_buff.get());
  } else if (dev_prop_type == DEVPROP_TYPE_STRING) {
    result = wstringToString((PWCHAR)drv_buff.get());
  } else if (dev_prop_type == DEVPROP_TYPE_FILETIME) {
    result =
        std::to_string(osquery::filetimeToUnixtime(*(PFILETIME)drv_buff.get()));
  } else {
    return Status::failure("Unhandled device property type " +
                           std::to_string(dev_prop_type));
  }

  return Status::success();
}

std::string getDriverImagePath(const std::string& service_key) {
  QueryData results;
  queryMultipleRegistryPaths({service_key + kRegSep + "ImagePath"}, results);

  if (results.empty()) {
    return "";
  }

  auto data_it = results[0].find("data");
  if (data_it == results[0].end()) {
    return "";
  }

  auto path = data_it->second;
  if (path.empty()) {
    return "";
  }

  return kNormalizeImage(path);
}

Status genServiceKeyMap(
    std::map<std::string, std::string>& services_image_map) {
  QueryData results;
  queryMultipleRegistryPaths({kServiceKeyPath + '%' + kRegSep + "ImagePath"},
                             results);

  // Something went wrong
  if (results.empty()) {
    return Status::failure("Failed to retrieve services image path cache");
  }

  for (auto& row : results) {
    auto key_it = row.find("key");
    auto data_it = row.find("data");
    if (key_it == row.end() || data_it == row.end()) {
      continue;
    }
    services_image_map[key_it->second] = kNormalizeImage(data_it->second);
  }
  return Status::success();
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  const Expected<WmiRequest, WmiError> wmiSignedDriverReq =
      WmiRequest::CreateWmiRequest("select * from Win32_PnPSignedDriver");

  // As our list relies on the WMI set we first query and bail if no results
  if (!wmiSignedDriverReq || wmiSignedDriverReq->results().empty()) {
    LOG(WARNING) << "Failed to query device drivers via WMI";
    return {};
  }
  const auto& wmi_results = wmiSignedDriverReq->results();

  auto dev_info_set = setupDevInfoSet(DIGCF_ALLCLASSES | DIGCF_PRESENT);
  if (dev_info_set == nullptr) {
    win32LogWARNING("Error getting device handle");
    return results;
  }

  std::map<std::wstring, Row> api_devices;
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
    WCHAR devId[MAX_DEVICE_ID_LEN] = {0};
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
      auto svc_key_it = svc_image_map.find(svc_key);
      if (svc_key_it != svc_image_map.end()) {
        r["image"] = svc_key_it->second;
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
    std::wstring devid;
    row.GetString(L"DeviceID", devid);
    r["device_id"] = wstringToString(devid);
    row.GetString("DeviceName", r["device_name"]);
    row.GetString("Description", r["description"]);
    row.GetString("DeviceClass", r["class"]);
    row.GetString("DriverVersion", r["version"]);
    row.GetString("Manufacturer", r["manufacturer"]);
    row.GetString("DriverProviderName", r["provider"]);

    bool is_signed;
    auto ret = row.GetBool("IsSigned", is_signed);
    if (ret.ok()) {
      r["signed"] = is_signed ? INTEGER(1) : INTEGER(0);
    } else {
      VLOG(1) << "Failed to get signature status for " << r["device_name"]
              << " with " << ret.getMessage();
      r["signed"] = "-1";
    }

    std::wstring inf_name;
    ret = row.GetString(L"InfName", inf_name);
    if (!ret.ok()) {
      VLOG(1) << "Failed to retrieve Inf name for " << r["device_name"]
              << " with " << ret.getMessage();
    } else {
      std::vector<WCHAR> inf(MAX_PATH, 0x0);
      unsigned long inf_len = 0;
      auto sdi_ret =
          SetupGetInfDriverStoreLocation(inf_name.c_str(),
                                         nullptr,
                                         nullptr,
                                         inf.data(),
                                         static_cast<unsigned long>(inf.size()),
                                         &inf_len);
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        inf.resize(inf_len);
        sdi_ret = SetupGetInfDriverStoreLocation(
            inf_name.c_str(),
            nullptr,
            nullptr,
            inf.data(),
            static_cast<unsigned long>(inf.size()),
            &inf_len);
      }
      if (sdi_ret != TRUE) {
        VLOG(1) << "Failed to derive full driver INF path for "
                << r["device_name"] << " with " << GetLastError();
        r["inf"] = wstringToString(inf_name);
      } else {
        r["inf"] = wstringToString(inf.data());
      }
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
