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
#include <osquery/utils/conversions/tryto.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/tables/system/windows/registry.h>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>

namespace osquery {
namespace tables {

DWORD GetBatteryState()
 {
#define GBS_HASBATTERY 0x1
#define GBS_ONBATTERY  0x2
  // Returned value includes GBS_HASBATTERY if the system has a 
  // non-UPS battery, and GBS_ONBATTERY if the system is running on 
  // a battery.
  //
  // dwResult & GBS_ONBATTERY means we have not yet found AC power.
  // dwResult & GBS_HASBATTERY means we have found a non-UPS battery.

  DWORD dwResult = GBS_ONBATTERY;

  // IOCTL_BATTERY_QUERY_INFORMATION,
  // enumerate the batteries and ask each one for information.

  HDEVINFO hdev =
            SetupDiGetClassDevs(&GUID_DEVCLASS_BATTERY, 
                                0, 
                                0, 
                                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (INVALID_HANDLE_VALUE != hdev)
   {
    // Limit search to 100 batteries max
    for (int idev = 0; idev < 100; idev++)
     {
      SP_DEVICE_INTERFACE_DATA did = {0};
      did.cbSize = sizeof(did);

      if (SetupDiEnumDeviceInterfaces(hdev,
                                      0,
                                      &GUID_DEVCLASS_BATTERY,
                                      idev,
                                      &did))
       {
        DWORD cbRequired = 0;

        SetupDiGetDeviceInterfaceDetail(hdev,
                                        &did,
                                        0,
                                        0,
                                        &cbRequired,
                                        0);
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
         {
          PSP_DEVICE_INTERFACE_DETAIL_DATA pdidd =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LPTR,
                                                         cbRequired);
          if (pdidd)
           {
            pdidd->cbSize = sizeof(*pdidd);
            if (SetupDiGetDeviceInterfaceDetail(hdev,
                                                &did,
                                                pdidd,
                                                cbRequired,
                                                &cbRequired,
                                                0))
             {
              // Enumerated a battery.  Ask it for information.
              HANDLE hBattery = 
                      CreateFile(pdidd->DevicePath,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL);
              if (INVALID_HANDLE_VALUE != hBattery)
               {
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
                                    NULL)
                    && bqi.BatteryTag)
                 {
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
                                      NULL))
                   {
                    // Only non-UPS system batteries count
                    if (bi.Capabilities & BATTERY_SYSTEM_BATTERY)
                     {
                      if (!(bi.Capabilities & BATTERY_IS_SHORT_TERM))
                       {
                        dwResult |= GBS_HASBATTERY;
// https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str
LOG(ERROR) << "chemistry " << bi.Chemistry; // Battery chemistry type
// Check for BATTERY_UNKNOWN_CAPACITY
LOG(ERROR) << "capacity " << bi.DesignedCapacity << " - " << bi.FullChargedCapacity;
LOG(ERROR) << "cycles " << bi.CycleCount;
                       }

                      // Query the battery status.
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
                                          NULL))
                       {
                        if (bs.PowerState & BATTERY_POWER_ON_LINE)
                         {
                          dwResult &= ~GBS_ONBATTERY;
                         }
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

LOG(WARNING) << "capacity from battery_status " << bs.Capacity;
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
                                          NULL))
                       {
LOG(WARNING) << bmd.Day << bmd.Month << bmd.Year;
                     } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
LOG(INFO) << "Battery does not seem to support manufacture date";
}

std::wstring name(255, L'\0');
bqi.InformationLevel = BatteryManufactureName;
                      if (DeviceIoControl(hBattery,
                                          IOCTL_BATTERY_QUERY_INFORMATION,
                                          &bqi,
                                          sizeof(bqi),
                                          name.data(),
                                          name.size(),
                                          &dwOut,
                                          NULL))
                       { // TODO handle buffer sizing
LOG(WARNING) << "manufacturer " << wstringToString(name);
                     } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
LOG(INFO) << "Battery does not seem to support manufacture name";
} else {
LOG(ERROR) << GetLastError();
}

std::wstring serial(255, L'\0');
bqi.InformationLevel = BatterySerialNumber;
                      if (DeviceIoControl(hBattery,
                                          IOCTL_BATTERY_QUERY_INFORMATION,
                                          &bqi,
                                          sizeof(bqi),
                                          serial.data(),
                                          serial.size(),
                                          &dwOut,
                                          NULL))
                       { // TODO handle buffer sizing
LOG(WARNING) << "serial " << wstringToString(serial);
                     } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
LOG(INFO) << "Battery does not seem to support serial";
} else {
LOG(ERROR) << GetLastError();
}

bqi.InformationLevel = BatteryDeviceName;
                      if (DeviceIoControl(hBattery,
                                          IOCTL_BATTERY_QUERY_INFORMATION,
                                          &bqi,
                                          sizeof(bqi),
                                          name.data(),
                                          name.size(),
                                          &dwOut,
                                          NULL))
                       { // TODO handle buffer sizing
LOG(WARNING) << "name " << wstringToString(name);
                     } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
LOG(INFO) << "Battery does not seem to support device name";
} else {
LOG(ERROR) << GetLastError();
}

ULONG temperature;
bqi.InformationLevel = BatteryTemperature;
                      if (DeviceIoControl(hBattery,
                                          IOCTL_BATTERY_QUERY_INFORMATION,
                                          &bqi,
                                          sizeof(bqi),
                                          &temperature,
                                          sizeof(temperature),
                                          &dwOut,
                                          NULL))
                       {
LOG(WARNING) << "temperature " << temperature;
                     } else if (ERROR_INVALID_FUNCTION == GetLastError()) {
LOG(INFO) << "Battery does not seem to support device temperature";
} else {
LOG(ERROR) << "temperature error " << GetLastError();
}

SYSTEM_POWER_STATUS sps;
if (GetSystemPowerStatus(&sps)) {
  LOG(WARNING) << "percent " << (unsigned int)sps.BatteryLifePercent;
  if (sps.BatteryLifeTime != -1) {
    LOG(WARNING) << "minutes remaining " << sps.BatteryLifeTime; // only makes sense during discharge
  }
} else {
LOG(ERROR) << "Failed to get system power status";
}


                   }
                 }
                CloseHandle(hBattery);
               }
             }
            LocalFree(pdidd);
           }
         }
       }
        else  if (ERROR_NO_MORE_ITEMS == GetLastError())
         {
          break;  // Enumeration failed - perhaps we're out of items
         }
     }
    SetupDiDestroyDeviceInfoList(hdev);
   }

  //  Final cleanup:  If we didn't find a battery, then presume that we
  //  are on AC power.

  if (!(dwResult & GBS_HASBATTERY))
    dwResult &= ~GBS_ONBATTERY;

  return dwResult;
 }

QueryData genDrivers(QueryContext& context) {
  QueryData results;

  GetBatteryState();

  return results;
}
} // namespace tables
} // namespace osquery
