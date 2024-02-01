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

#include <windows.h>
#include <ioapiset.h>
#include <Batclass.h>
#include <Poclass.h>
#include <setupapi.h>
#include <devguid.h>
#include <devioctl.h>

// clang-format on

#include <osquery/core/windows/wmi.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/errno.h>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>

namespace osquery {
namespace tables {

std::string batteryQueryInformationString(
    HANDLE hBattery,
    ULONG batteryTag,
    BATTERY_QUERY_INFORMATION_LEVEL informationLevel) {
  BATTERY_QUERY_INFORMATION bqi = {0};
  bqi.InformationLevel = informationLevel;
  bqi.BatteryTag = batteryTag;
  // 1025 characters should be way more than enough for the values retrieved
  // from this function. It shouldn't overflow anyway due to providing size in
  // the function.
  std::wstring resWstring(1025, L'\0');
  DWORD resSize(0);

  if (!DeviceIoControl(hBattery,
                       IOCTL_BATTERY_QUERY_INFORMATION,
                       &bqi,
                       sizeof(bqi),
                       resWstring.data(),
                       resWstring.size() * sizeof(wchar_t),
                       nullptr,
                       nullptr)) {
    if (ERROR_INVALID_FUNCTION == GetLastError()) {
      LOG(INFO) << "Battery does not support information level "
                << informationLevel;
    } else {
      LOG(ERROR) << "Failed to get battery information level "
                 << informationLevel << ": code " << GetLastError();
    }
    return "";
  }

  return wstringToString(resWstring);
}

void GetBatteryState() {
  // Adapted from Microsoft example:
  // https://learn.microsoft.com/en-us/windows/win32/power/enumerating-battery-devices

  // IOCTL_BATTERY_QUERY_INFORMATION,
  // enumerate the batteries and ask each one for information.

  HDEVINFO hdev = SetupDiGetClassDevs(
      &GUID_DEVCLASS_BATTERY, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (INVALID_HANDLE_VALUE != hdev) {
    // Limit search to 100 batteries max
    for (int idev = 0; idev < 100; idev++) {
      SP_DEVICE_INTERFACE_DATA did = {0};
      did.cbSize = sizeof(did);

      if (SetupDiEnumDeviceInterfaces(
              hdev, 0, &GUID_DEVCLASS_BATTERY, idev, &did)) {
        auto const hdevGuard =
            scope_guard::create([&]() { SetupDiDestroyDeviceInfoList(hdev); });
        DWORD cbRequired = 0;

        SetupDiGetDeviceInterfaceDetail(hdev, &did, 0, 0, &cbRequired, 0);
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
          PSP_DEVICE_INTERFACE_DETAIL_DATA pdidd =
              (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LPTR, cbRequired);
          if (pdidd) {
            auto const pdiddGuard =
                scope_guard::create([&]() { LocalFree(pdidd); });
            pdidd->cbSize = sizeof(*pdidd);
            if (SetupDiGetDeviceInterfaceDetail(
                    hdev, &did, pdidd, cbRequired, &cbRequired, 0)) {
              // Enumerated a battery.  Ask it for information.
              HANDLE hBattery = CreateFile(pdidd->DevicePath,
                                           GENERIC_READ | GENERIC_WRITE,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                                           nullptr,
                                           OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL,
                                           nullptr);
              if (INVALID_HANDLE_VALUE != hBattery) {
                auto const hBatteryGuard =
                    scope_guard::create([&]() { CloseHandle(hBattery); });

                // Ask the battery for its tag.
                BATTERY_QUERY_INFORMATION bqi = {0};

                DWORD dwWait = 0;
                DWORD dwOut;

                if (DeviceIoControl(hBattery,
                                    IOCTL_BATTERY_QUERY_TAG,
                                    &dwWait,
                                    sizeof(dwWait),
                                    &bqi.BatteryTag,
                                    sizeof(bqi.BatteryTag),
                                    &dwOut,
                                    nullptr) &&
                    bqi.BatteryTag) {
                  // With the tag, you can query the battery info.
                  BATTERY_INFORMATION bi = {0};
                  bqi.InformationLevel = BatteryInformation;

                  if (DeviceIoControl(hBattery,
                                      IOCTL_BATTERY_QUERY_INFORMATION,
                                      &bqi,
                                      sizeof(bqi),
                                      &bi,
                                      sizeof(bi),
                                      &dwOut,
                                      nullptr)) {
                    // Only non-UPS system batteries count
                    if (bi.Capabilities & BATTERY_SYSTEM_BATTERY) {
                      if (!(bi.Capabilities & BATTERY_IS_SHORT_TERM)) {
                        // https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str
                        LOG(ERROR) << "chemistry "
                                   << bi.Chemistry; // Battery chemistry type
                        // Check for BATTERY_UNKNOWN_CAPACITY
                        LOG(ERROR) << "capacity " << bi.DesignedCapacity
                                   << " - " << bi.FullChargedCapacity;
                        LOG(ERROR) << "cycles " << bi.CycleCount;
                      }

                      // Query the battery power status.
                      BATTERY_WAIT_STATUS bws = {0};
                      bws.BatteryTag = bqi.BatteryTag;

                      BATTERY_STATUS bs;
                      if (DeviceIoControl(hBattery,
                                          IOCTL_BATTERY_QUERY_STATUS,
                                          &bws,
                                          sizeof(bws),
                                          &bs,
                                          sizeof(bs),
                                          &dwOut,
                                          nullptr)) {
                        // https://learn.microsoft.com/en-us/windows/win32/power/battery-wait-status-str
                        if (bs.PowerState & BATTERY_CHARGING) {
                          LOG(WARNING) << "charging";
                        }
                        if (bs.PowerState & BATTERY_DISCHARGING) {
                          LOG(WARNING) << "discharging";
                        }
                        if (bs.PowerState & BATTERY_POWER_ON_LINE) {
                          LOG(WARNING) << "powered";
                        }

                        LOG(WARNING)
                            << "capacity from battery_status " << bs.Capacity;
                        LOG(WARNING) << "voltage " << bs.Voltage;
                        LOG(WARNING) << "rate " << bs.Rate;
                      }
                    }

                    bqi.InformationLevel = BatteryManufactureDate;
                    BATTERY_MANUFACTURE_DATE bmd;
                    if (DeviceIoControl(hBattery,
                                        IOCTL_BATTERY_QUERY_INFORMATION,
                                        &bqi,
                                        sizeof(bqi),
                                        &bmd,
                                        sizeof(bmd),
                                        &dwOut,
                                        nullptr)) {
                      LOG(WARNING) << bmd.Day << bmd.Month << bmd.Year;
                    } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
                      LOG(INFO) << "Battery does not support "
                                   "manufacture date";
                    }

                    std::string result = batteryQueryInformationString(
                        hBattery, bqi.BatteryTag, BatteryManufactureName);
                    LOG(WARNING) << "manufacturer " << result;

                    LOG(WARNING)
                        << "serial "
                        << batteryQueryInformationString(
                               hBattery, bqi.BatteryTag, BatterySerialNumber);

                    LOG(WARNING)
                        << "name "
                        << batteryQueryInformationString(
                               hBattery, bqi.BatteryTag, BatteryDeviceName);

                    ULONG temperature;
                    bqi.InformationLevel = BatteryTemperature;
                    if (DeviceIoControl(hBattery,
                                        IOCTL_BATTERY_QUERY_INFORMATION,
                                        &bqi,
                                        sizeof(bqi),
                                        &temperature,
                                        sizeof(temperature),
                                        &dwOut,
                                        nullptr)) {
                      LOG(WARNING) << "temperature " << temperature;
                    } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
                      LOG(INFO) << "Battery does not seem to support device "
                                   "temperature";
                    } else {
                      LOG(ERROR) << "temperature error " << GetLastError();
                    }

                    SYSTEM_POWER_STATUS sps;
                    if (GetSystemPowerStatus(&sps)) {
                      LOG(WARNING)
                          << "percent " << (unsigned int)sps.BatteryLifePercent;
                      if (sps.BatteryLifeTime != -1) {
                        LOG(WARNING) << "minutes remaining "
                                     << sps.BatteryLifeTime; // only makes sense
                                                             // during discharge
                      }
                    } else {
                      LOG(ERROR) << "Failed to get system power status";
                    }

                    // Once we find one battery, no need to do anything else
                    return;
                  }
                }
              }
            }
          }
        }
      } else if (ERROR_NO_MORE_ITEMS == GetLastError()) {
        break; // Enumeration failed - perhaps we're out of items
      }
    }
  }
}

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  GetBatteryState();

  return results;
}
} // namespace tables
} // namespace osquery
