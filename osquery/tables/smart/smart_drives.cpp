/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <smartmontools/libsmartctl.h>
#include <smartmontools/smartctl_errs.h>

#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"
#include "osquery/tables/smart/smart_drives.h"

namespace osquery {
namespace tables {

static inline std::ostream& operator<<(
    std::ostream& stream, const std::vector<hardwareDriver>& devs) {
  for (const auto& dev : devs) {
    stream << " " << dev.driver;
  }

  return stream;
}

/// Static map of supported controller types.
static const std::map<std::string, hardwareDriver>
    kSmartExplicitDriverToDevice = {
        {"megaraid_sas", hardwareDriver{"megaraid,", 127}},
        {"hpsa", hardwareDriver{"cciss,", 14}},
};

/// Gets all devices of class 'Mass storage controller'.
void getStorageCtlerClassDrivers(std::vector<std::string>& results) {
  auto devices = SQL::selectAllFrom("pci_devices");
  for (const auto& device : devices) {
    auto pciClass = device.find("pci_class");
    auto driver = device.find("driver");
    if (pciClass != device.end() &&
        pciClass->second == "Mass storage controller" &&
        driver != device.end()) {
      auto driverName = driver->second;
      auto i = std::lower_bound(results.begin(), results.end(), driverName);
      if (i == results.end() || driverName < *i) {
        results.insert(i, std::move(driverName));
      }
    }
  }
}

/// Gets supported hardwareDriver from system storage controllers.
static inline void getSmartCtlDeviceType(
    const std::vector<std::string>& storageDrivers,
    std::vector<hardwareDriver>& types) {
  for (const auto& driver : storageDrivers) {
    auto hwDriver = kSmartExplicitDriverToDevice.find(driver);
    if (hwDriver != kSmartExplicitDriverToDevice.end()) {
      types.push_back(hwDriver->second);
    }
  }
}

/// Utility function for traversing system devices.
void walkBlkDevices(std::function<void(const std::string& devname,
                                       hardwareDriver* type)> handleDevF) {
  if (getuid() != 0 || geteuid() != 0) {
    LOG(WARNING) << "Need root access for smart information";
    return;
  }

  std::vector<std::string> storageDrivers;
  getStorageCtlerClassDrivers(storageDrivers);

  std::vector<hardwareDriver> types;
  getSmartCtlDeviceType(storageDrivers, types);

  if (types.size() > 1) {
    LOG(WARNING) << "Found more than 1 hardware storage controller:" << types
                 << "; only handling the first";
    return;
  }

  hardwareDriver* type = nullptr;
  if (types.size() == 1) {
    type = &(types[0]);
  }

  auto blkDevices = SQL::selectAllFrom("block_devices");
  for (const auto& device : blkDevices) {
    auto size = device.find("size");
    auto name = device.find("name");
    if (size != device.end() && size->second != "0" && size->second != "" &&
        name != device.end()) {
      handleDevF(name->second, type);
    }
  }
}

void querySmartDevices(
    libsmartctl::ClientInterface& c,
    std::function<
        void(std::function<void(const std::string&, hardwareDriver*)>)> walkF,
    QueryData& results) {
  // hwInfo is for tracking info retrieve with an explicit HW controller.  It is
  // indexed by serial_number, since that's how you correlate the data with
  // auto-detect retrieved SMART info.
  std::map<std::string, Row> hwInfo;

  // Flag for indicating found state utilizing hardware driver info.
  bool found = false;
  walkF([&](const std::string& devname, hardwareDriver* type) {
    // Get autodetected info..
    auto resp = c.getDevInfo(devname, "");
    if (resp.err != NOERR) {
      LOG(INFO) << "There was an error retrieving drive information: "
                << libsmartctl::errStr(resp.err);
      // Don't return here, keep searching with fulltype.
    } else {
      resp.content["device_name"] = devname;
      results.push_back(std::move(resp.content));
    }

    // Get info via HW controllers if not found yet
    if (found) {
      return;
    }

    if (type == nullptr) {
      found = true;
      return;
    }

    // No need to check each individual software partition since they will
    // examined at the HW level below.
    if (devname.substr(devname.length() - 1).find_last_of("0123456789") !=
        std::string::npos) {
      return;
    }

    // We now try to find device information based on any explicit storage
    // controller info.  Once we find one, we can search until the max ID of
    // that controller, and assume that all information with that controller has
    // been retrived.
    for (size_t i = 0; i <= type->maxID; i++) {
      std::string fullType = type->driver + std::to_string(i);

      auto cantId = c.cantIdDev(devname, fullType);
      if (cantId.err != NOERR) {
        LOG(INFO) << "Error while trying to identify device: "
                  << libsmartctl::errStr(cantId.err);
        continue;
      }
      // If device is not identifiable, the type is invalid, skip..
      if (cantId.content) {
        continue;
      }

      resp = c.getDevInfo(devname, fullType);
      if (resp.err != NOERR) {
        LOG(WARNING) << "There was an error retrieving drive information with "
                        "hardware driver: "
                     << libsmartctl::errStr(resp.err);
        return;
      }
      // Only consider found if no error was returned.
      found = true;

      resp.content["disk_id"] = std::to_string(i);
      // Change device type to driver_type
      resp.content["driver_type"] =
          type->driver.substr(0, type->driver.length() - 1);

      auto serial = resp.content.find("serial_number");
      if (serial != resp.content.end()) {
        hwInfo[serial->second] = resp.content;
      };
    }

    return;
  });

  // Join results..
  for (auto& entry : hwInfo) {
    bool matched = false;
    for (auto& row : results) {
      auto serial = row.find("serial_number");
      if (serial == row.end()) {
        continue;
      }

      if (entry.first == serial->second) {
        matched = true;
        row["disk_id"] = entry.second["disk_id"];
        row["driver_type"] = entry.second["driver_type"];
      }
    }

    // If we don't find a serial_number match, we assume this drive information
    // can only be retrieved by explicitely passing driver information.
    if (!matched) {
      results.push_back(std::move(entry.second));
    }
  }
}

QueryData genSmartInfo(QueryContext& context) {
  QueryData results;
  libsmartctl::Client c;
  querySmartDevices(c, walkBlkDevices, results);

  return results;
}
} // namespace tables
} // namespace osquery
