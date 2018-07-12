/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <smartmontools/libsmartctl.h>
#include <smartmontools/smartctl_errs.h>

#include <iterator>

#include <osquery/tables.h>

#include "osquery/tables/smart/smart_drives.h"

namespace osquery {
namespace tables {

class QuerySmartDevicesTest : public ::testing::Test {};

/**
 * @brief Mock client to simulate calls to libsmartctl.
 *
 * Utilizing constructor arg to determine device hits and misses.
 *
 * Naming convention for devices: `some_name_[a - z]`
 * Serial numbers are always the reverse of the name.
 * Device names should always be in order of the downcased alphabet suffix
 * where the place of letter in the alphabet represents the index of utilized
 * with the HW controller type info.  For example:
 * `device_a` while also yield to the entry requested with
 * `getDevInfo("some_device_a", "some_ctler,0")`.
 */
class MockLibsmartctlClient : public libsmartctl::ClientInterface {
 private:
  std::map<std::string, std::map<std::string, std::string>> data_;

 public:
  libsmartctl::CantIdDevResp cantIdDev(std::string const& devname,
                                       std::string const& type) override {
    libsmartctl::CantIdDevResp resp;

    if (data_.find(devname) != data_.end()) {
      resp.content = false;
    } else {
      resp.content = true;
    }

    return resp;
  }

  libsmartctl::DevInfoResp getDevInfo(std::string const& devname,
                                      std::string const& type = "") override {
    libsmartctl::DevInfoResp resp;

    if (type.empty()) {
      auto deviceData = data_.find(devname);
      if (deviceData != data_.end()) {
        resp.content = deviceData->second;
      } else {
        resp.err = GETDEVICERR;
      }

    } else {
      // type is the full type of the device, which is always "<controller
      // name>, <N>".  We can gaurantee uniqueness by pinning the the number N
      // to the nth element of the STL.
      auto n = type.at(type.find(",") + 1);
      auto nIt = std::next(data_.begin(), n - '0');
      if (nIt != data_.end()) {
        resp.content = nIt->second;
      } else {
        resp.err = GETDEVICERR;
      }
    }

    return resp;
  }

  libsmartctl::DevVendorAttrsResp getDevVendorAttrs(
      std::string const& devname, std::string const& type = "") override {
    return libsmartctl::DevVendorAttrsResp{};
  }

 public:
  MockLibsmartctlClient(
      std::map<std::string, std::map<std::string, std::string>>& data)
      : data_(data) {}
};

/// Generates mock devices to test against.
std::function<void(std::function<void(const std::string&, hardwareDriver*)>)>
genMockWalkFunc(const std::map<std::string, hardwareDriver*>& devices) {
  return
      [&](std::function<void(const std::string&, hardwareDriver*)> handleDevF) {
        for (const auto& device : devices) {
          handleDevF(device.first, device.second);
        }
      };
}

/// Generates mock SMART device data.
std::map<std::string, std::string> genMockDeviceData(
    const std::string& devname) {
  std::string serial(devname);
  std::reverse(serial.begin(), serial.end());
  std::map<std::string, std::string> data = {
      {"serial_number", serial},
  };

  return data;
}

TEST_F(QuerySmartDevicesTest, no_hw_controllers) {
  // Stub SMART data.
  std::map<std::string, std::map<std::string, std::string>> mockdb = {
      {"device_a", genMockDeviceData("device_a")},
      {"device_b", genMockDeviceData("device_b")},
  };

  std::map<std::string, hardwareDriver*> devices = {
      {"device_a", nullptr},
      {"device_b", nullptr},
  };

  QueryData expected = {
      {
          {"device_name", "device_a"},
          {"serial_number", "a_ecived"},
      },
      {
          {"device_name", "device_b"},
          {"serial_number", "b_ecived"},
      },
  };

  MockLibsmartctlClient mockClient(mockdb);
  QueryData got;
  querySmartDevices(mockClient, genMockWalkFunc(devices), got);

  EXPECT_EQ(got, expected);
}

TEST_F(QuerySmartDevicesTest, with_hw_controllers) {
  // Stub SMART data.
  std::map<std::string, std::map<std::string, std::string>> mockdb = {
      {"device_a", genMockDeviceData("device_a")},
      {"device_b", genMockDeviceData("device_b")},
  };

  hardwareDriver driver = {
      "foobar,",
      5,
  };

  std::map<std::string, hardwareDriver*> devices = {
      {"device_a", &driver},
      {"device_b", &driver},
  };

  QueryData expected = {
      {
          {"device_name", "device_a"},
          {"serial_number", "a_ecived"},
          {"disk_id", "0"},
          {"driver_type", "foobar"},
      },
      {
          {"device_name", "device_b"},
          {"serial_number", "b_ecived"},
          {"disk_id", "1"},
          {"driver_type", "foobar"},
      },
  };

  MockLibsmartctlClient mockClient(mockdb);
  QueryData got;
  querySmartDevices(mockClient, genMockWalkFunc(devices), got);

  EXPECT_EQ(got, expected);
}

} // namespace tables
} // namespace osquery
