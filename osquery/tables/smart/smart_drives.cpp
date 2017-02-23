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
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

/* @brief Represents a hardware driver type that SMART api can you use to query
 * device information.
 *
 * @param driver name of SMART controller driver
 * @param maxID max ID number of which disks on the controller is monitored
 */
struct hardwareDriver {
  std::string driver;
  size_t maxID;
};

std::ostream& operator<<(std::ostream& stream,
                         const std::vector<hardwareDriver>& devs) {
  for (const auto& dev : devs) {
    stream << " " << dev.driver;
  }

  return stream;
}

/// delUdevDevice is a lambda function meant to be used with smart pointers for
/// unreffing for udev_device pointers.
auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };

/// Static map of supported controller types.
static const std::map<std::string, hardwareDriver>
    kSMARTExplicitDriverToDevice = {
        {"megaraid_sas", hardwareDriver{"megaraid,", 127}},
        {"hpsa", hardwareDriver{"cciss,", 14}},
};

/// Utility function for traversing sysFs.
void walkUdevSubSystem(
    std::string subsystem,
    std::function<void(udev_list_entry* const, udev* const)> handleDevF) {
  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> ud(udev_new(), delUdev);

  if (ud.get() == nullptr) {
    LOG(ERROR) << "Could not get libudev handle";
    return;
  }

  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> enumerate(
      udev_enumerate_new(ud.get()), delUdevEnum);

  udev_enumerate_add_match_subsystem(enumerate.get(), subsystem.c_str());
  udev_enumerate_scan_devices(enumerate.get());
  udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate.get());

  udev_list_entry* dev_list_entry;
  udev_list_entry_foreach(dev_list_entry, devices) {
    handleDevF(dev_list_entry, ud.get());
  }
}

/// Gets all block devices of system.
std::vector<std::string> getBlkDevices() {
  std::vector<std::string> results;

  walkUdevSubSystem(
      "block", [&results](udev_list_entry* const entry, udev* const ud) {
        auto path = udev_list_entry_get_name(entry);
        if (path == nullptr) {
          return;
        }
        if (std::strstr(path, "virtual")) {
          return;
        }

        std::unique_ptr<udev_device, decltype(delUdevDevice)> dev(
            udev_device_new_from_syspath(ud, path), delUdevDevice);
        if (dev.get() == nullptr) {
          return;
        }

        results.push_back(udev_device_get_devnode(dev.get()));
      });

  return results;
}

/// Gets all devices of class 'Mass storage controller'.
std::vector<std::string> getStorageCtlerClassDrivers() {
  std::vector<std::string> results;

  walkUdevSubSystem(
      "pci", [&results](udev_list_entry* const entry, udev* const ud) {
        auto path = udev_list_entry_get_name(entry);
        if (path == nullptr) {
          return;
        }

        std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
            udev_device_new_from_syspath(ud, path), delUdevDevice);
        if (device.get() == nullptr) {
          return;
        }

        if (UdevEventPublisher::getValue(device.get(),
                                         "ID_PCI_CLASS_FROM_DATABASE") ==
            "Mass storage controller") {
          auto driverName =
              UdevEventPublisher::getValue(device.get(), "DRIVER");

          auto i = std::lower_bound(results.begin(), results.end(), driverName);
          if (i == results.end() || driverName < *i) {
            results.insert(i, driverName);
          }
        }
      });

  return results;
}

/// Gets supported hardwareDriver from system storage controllers.
static inline void getSmartCtlDeviceType(
    const std::vector<std::string>& storageDrivers,
    std::vector<hardwareDriver>& types) {
  for (auto const& driver : storageDrivers) {
    if (kSMARTExplicitDriverToDevice.find(driver) !=
        kSMARTExplicitDriverToDevice.end()) {
      types.push_back(kSMARTExplicitDriverToDevice.at(driver));
    }
  }
}

/// Utility function for traversing system devices.
void walkDevices(std::function<bool(libsmartctl::Client& c,
                                    const std::string& devname,
                                    hardwareDriver* type)> handleDevF) {
  if (getuid() || geteuid()) {
    LOG(WARNING) << "Need root access for smart information";
  }

  QueryData results;
  libsmartctl::Client c;

  auto storageDrivers = getStorageCtlerClassDrivers();

  std::vector<hardwareDriver> types;
  getSmartCtlDeviceType(storageDrivers, types);

  if (types.size() > 1) {
    LOG(WARNING) << "Found more than 1 hardware storage controller:" << types
                 << "; only handling the first";
    return;
  }

  hardwareDriver* type{nullptr};
  if (types.size() == 1) {
    type = &(types[0]);
  }

  std::vector<std::string> devs = getBlkDevices();
  for (const auto& dev : devs) {
    if (handleDevF(c, dev, type)) {
      break;
    };
  }
}

QueryData genSmartInfo(QueryContext& context) {
  QueryData results;
  /* hwInfo is for tracking info retrieve with an explicit HW controller.  It is
   * indexed by serial_number, since that's how you correlate the data with
   * auto-detect retrieved SMART info. */
  std::map<std::string, Row> hwInfo;

  bool found{false};
  walkDevices([&](libsmartctl::Client& c,
                  const std::string& devname,
                  hardwareDriver* type) {
    // Get auto info..
    auto resp = c.getDevInfo(devname, "");
    if (resp.err != NOERR) {
      LOG(WARNING) << "There was an error retrieving drive information: "
                   << libsmartctl::errStr(resp.err);

    } else {
      resp.content["device_name"] = devname;
      results.push_back(std::move(resp.content));
    }

    // Get info via HW controllers if not found yet
    if (found) {
      return false;
    }

    if (type == nullptr) {
      found = true;
      return false;
    }

    if (devname.substr(devname.length() - 1).find_last_of("0123456789") !=
        std::string::npos) {
      return false;
    }

    for (size_t i = 0; i <= type->maxID; i++) {
      std::string fullType = type->driver + std::to_string(i);

      auto cantId = c.cantIdDev(devname, fullType);
      if (cantId.err != NOERR) {
        LOG(INFO) << "Error while trying to identify device: "
                  << libsmartctl::errStr(cantId.err);
        continue;
      }
      // If device is not identifiable, the type is invalid, skip
      if (cantId.content) {
        continue;
      }

      resp = c.getDevInfo(devname, fullType);
      if (resp.err != NOERR) {
        LOG(WARNING) << "There was an error retrieving drive information with "
                        "hardware driver: "
                     << libsmartctl::errStr(resp.err);
        return false;
      }
      // Only consider found if no error was returned.
      found = true;

      resp.content["disk_id"] = std::to_string(i);
      // Change device type to driver_type
      resp.content["driver_type"] =
          type->driver.substr(0, type->driver.length() - 1);

      if (resp.content.find("serial_number") != resp.content.end()) {
        hwInfo[resp.content["serial_number"]] = resp.content;
      };
    }

    return false;
  });

  // Join results..
  for (auto& entry : hwInfo) {
    bool matched{false};
    for (auto& row : results) {
      if (row.find("serial_number") == row.end()) {
        continue;
      }

      if (entry.first == row["serial_number"]) {
        matched = true;
        row["disk_id"] = entry.second["disk_id"];
        row["driver_type"] = entry.second["driver_type"];
      }
    }

    /* If we don't find a serial_number match, we assume this drive information
     * can only be retrieved by explicitely passing driver information. */
    if (!matched) {
      results.push_back(std::move(entry.second));
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
