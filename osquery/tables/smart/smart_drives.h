/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <smartmontools/libsmartctl.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief Represents a hardware driver type that SMART api can you use to query
 * device information.
 *
 * @param driver name of SMART controller driver
 * @param maxID max ID number of which disks on the controller is monitored
 */
struct hardwareDriver {
  std::string driver;
  size_t maxID;
};

/**
 * @brief Queries SMART devices on the system by autodetection and explicit
 * storage controller arguments.
 *
 * @param client libsmartctl client
 * @param walk_func function that walks the system devices and runs the handler
 * function on each device
 * @param results reference to QueryData to store results in
 */
void querySmartDevices(
    libsmartctl::ClientInterface& client,
    std::function<void(
        std::function<void(const std::string&, hardwareDriver*)>)> walk_func,
    QueryData& results);

} // namespace tables
} // namespace osquery
