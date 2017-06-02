/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once
#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <Windows.h>
#include <initguid.h>
// clang-format on
#include <Devpkey.h>
#include <Devpropdef.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

const auto closeInfoSet = [](auto infoset) {
  SetupDiDestroyDeviceInfoList(infoset);
};

using device_infoset_t = std::unique_ptr<void, decltype(closeInfoSet)>;

/*
 * @brief Build a device infoset. This must be done before calling the
 * other functions in this file or other SetupAPI functions.
 *
 * @param flags Bitwise OR of flags to provide to SetupDiGetClassDevs.
 * The default value results in devices from all classes that are currently
 * present on the system
 * @return A unique pointer to the populated infoset
 */
device_infoset_t setupDevInfoSet(const DWORD flags = DIGCF_ALLCLASSES |
                                                     DIGCF_PRESENT);

/*
 * @brief Build a list of devices from an infoset
 *
 * @param infoset the populated infoset containing the devices to extract
 * @param rDevices a vector that will be populated with the device info structs
 */
Status getDeviceList(const device_infoset_t& infoset,
                     std::vector<SP_DEVINFO_DATA>& rDevices);
/*
 * @brief Get info for the active driver for a device
 *
 * A device can have no more than 1 active/selected driver associated with it.
 * This function will return information about the currently selected driver, if
 * one exists.
 *
 * @param infoset A populated info set containing the device to grab the driver
 * for
 * @param device The device to grab driver info for
 * @param rDriverInfo Will be populated with driver information if a driver was
 * found
 * @param rDriverInfoDetail Will be populated with additional driver information
 * if a driver was found
 * @return success if a driver was found and information was populated.
 */
Status getDeviceDriverInfo(const device_infoset_t& infoset,
                           SP_DEVINFO_DATA& device,
                           SP_DRVINFO_DATA& rDriverInfo,
                           SP_DRVINFO_DETAIL_DATA& rDriverInfoDetail);
/*
 * @brief Get specific device or driver properties
 *
 * This can be used to get any of the properties defined in Devpkey.h. Many of
 * these properties are not readily available in the device info structs like
 * SP_DEVINFO_DATA.
 *
 * @param infoset A populated infoset containing the device
 * @param device The device to grab the property for
 * @param prop The property to grab
 * @param result Will be populated with the value of the property. If the
 * property is not set for this device, result will be an empty string.
 * @return success if the property value was retrieved.
 */
Status getDeviceProperty(const device_infoset_t& infoset,
                         SP_DEVINFO_DATA& device,
                         const DEVPROPKEY& prop,
                         std::string& result);
} // namespace tables
} // namespace osquery
