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

#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/errno.h>

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
  // the DeviceIoControl call.
  std::wstring resWstring(1025, L'\0');
  DWORD resSize(0);

  if (!DeviceIoControl(hBattery,
                       IOCTL_BATTERY_QUERY_INFORMATION,
                       &bqi,
                       sizeof(bqi),
                       resWstring.data(),
                       static_cast<DWORD>(resWstring.size()) * sizeof(wchar_t),
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

QueryData genBatteryInfo(QueryContext& context) {
  QueryData results;

  // Adapted from Microsoft example:
  // https://learn.microsoft.com/en-us/windows/win32/power/enumerating-battery-devices
  // Enumerate the batteries and ask each one for information.
  HDEVINFO hdev = SetupDiGetClassDevs(
      &GUID_DEVCLASS_BATTERY, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (hdev == INVALID_HANDLE_VALUE) {
    LOG(ERROR) << "Failed to initialize handle for enumerating batteries: "
               << GetLastError();
    return results;
  }
  auto const hdevGuard =
      scope_guard::create([&]() { SetupDiDestroyDeviceInfoList(hdev); });

  // Limit search to 100 batteries max
  for (int idev = 0; idev < 100; idev++) {
    SP_DEVICE_INTERFACE_DATA did = {0};
    did.cbSize = sizeof(did);

    if (!SetupDiEnumDeviceInterfaces(
            hdev, 0, &GUID_DEVCLASS_BATTERY, idev, &did)) {
      if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        // Only log if it's an unexpected error
        LOG(ERROR) << "Failed to set up enumeration for batteries: "
                   << GetLastError();
      }
      break;
    }

    DWORD cbRequired = 0;
    SetupDiGetDeviceInterfaceDetail(hdev, &did, 0, 0, &cbRequired, 0);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      LOG(ERROR)
          << "Failed to get buffer size for get device interface detail: "
          << GetLastError();
      continue;
    }

    PSP_DEVICE_INTERFACE_DETAIL_DATA pdidd =
        (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LPTR, cbRequired);
    if (pdidd == nullptr) {
      LOG(ERROR) << "Failed to allocate buffer for device interface detail: "
                 << GetLastError();
      continue;
    }
    auto const pdiddGuard = scope_guard::create([&]() { LocalFree(pdidd); });

    pdidd->cbSize = sizeof(*pdidd);
    if (!SetupDiGetDeviceInterfaceDetail(
            hdev, &did, pdidd, cbRequired, &cbRequired, 0)) {
      LOG(ERROR) << "Failed to get battery device detail: " << GetLastError();
      continue;
    }

    // Enumerated a battery.  Ask it for information.
    HANDLE hBattery = CreateFile(pdidd->DevicePath,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
    if (hBattery == INVALID_HANDLE_VALUE) {
      LOG(ERROR) << "Failed to open handle for battery device "
                 << wstringToString(pdidd->DevicePath) << ": "
                 << GetLastError();
      continue;
    }
    auto const hBatteryGuard =
        scope_guard::create([&]() { CloseHandle(hBattery); });

    // Ask the battery for its tag - needed for later queries
    BATTERY_QUERY_INFORMATION bqi = {0};
    DWORD dwWait = 0; // do not wait for a battery, return immediately
    DWORD dwOut;
    if (!(DeviceIoControl(hBattery,
                          IOCTL_BATTERY_QUERY_TAG,
                          &dwWait,
                          sizeof(dwWait),
                          &bqi.BatteryTag,
                          sizeof(bqi.BatteryTag),
                          &dwOut,
                          nullptr) &&
          bqi.BatteryTag)) {
      LOG(ERROR) << "Failed to get tag for battery device "
                 << wstringToString(pdidd->DevicePath) << ": "
                 << GetLastError();
      continue;
    }

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
      if (!(bi.Capabilities & BATTERY_SYSTEM_BATTERY) ||
          (bi.Capabilities & BATTERY_IS_SHORT_TERM)) {
        continue;
      }

      if (bi.Capabilities & BATTERY_CAPACITY_RELATIVE) {
        LOG(WARNING) << "Battery is reporting in unknown (relative) units. "
                        "Values may not be in mAh, mA, and mV.";
      }

      Row row;

      // Some possible values for chemistry, though we already have
      // seen LiP which is not listed
      // https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str
      row["chemistry"] = SQL_TEXT(bi.Chemistry);

      // Assume that 12 volts is the intended voltage for the
      // battery in order to convert from the mWh units that
      // Microsoft provides to match the mAh units that the battery
      // table already uses for macOS.
      const int designedVoltage = 12;
      row["max_capacity"] = INTEGER(bi.FullChargedCapacity / designedVoltage);
      row["designed_capacity"] = INTEGER(bi.DesignedCapacity / designedVoltage);
      if (bi.CycleCount != 0) {
        row["cycle_count"] = INTEGER(bi.CycleCount);
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
        if (bs.PowerState & BATTERY_POWER_ON_LINE) {
          row["state"] = "AC Power";
          row["charging"] = INTEGER((bs.PowerState & BATTERY_CHARGING) > 0);
        } else if (bs.PowerState & BATTERY_DISCHARGING) {
          row["state"] = "Battery Power";
          row["charging"] = INTEGER(0);
        }
        row["charged"] = INTEGER(bs.Capacity == bi.FullChargedCapacity);
        row["current_capacity"] = INTEGER(bs.Capacity / designedVoltage);
        row["voltage"] = INTEGER(bs.Voltage);
        if (bs.Voltage > 0) {
          row["amperage"] = INTEGER((1000 * static_cast<int>(bs.Rate)) /
                                    static_cast<int>(bs.Voltage));
        } else {
          LOG(WARNING) << "Battery table read a voltage of 0.";
        }
        if (bs.Capacity != bi.FullChargedCapacity && bs.Rate > 0) {
          row["minutes_to_full_charge"] =
              INTEGER(60 * (bi.FullChargedCapacity - bs.Capacity) / bs.Rate);
        }
      }

      SYSTEM_POWER_STATUS sps;
      if (GetSystemPowerStatus(&sps)) {
        if (sps.BatteryLifePercent != -1) {
          row["percent_remaining"] =
              INTEGER((unsigned int)sps.BatteryLifePercent);
        }
        if (sps.BatteryLifeTime != -1) {
          row["minutes_until_empty"] =
              INTEGER(sps.BatteryLifeTime / 60); // convert seconds to minutes
        }
      } else {
        LOG(WARNING) << "Failed to get system power status";
      }

      row["manufacturer"] = batteryQueryInformationString(
          hBattery, bqi.BatteryTag, BatteryManufactureName);

      row["serial_number"] = batteryQueryInformationString(
          hBattery, bqi.BatteryTag, BatterySerialNumber);

      row["model"] = batteryQueryInformationString(
          hBattery, bqi.BatteryTag, BatteryDeviceName);

      results.push_back(row);
    }
  }

  if (results.empty()) {
    VLOG(1) << "Battery table did not find a system battery";
  }
  return results;
}
} // namespace tables
} // namespace osquery