/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/core/sql/query_data.h>

namespace osquery {
namespace tables {

bool parseUSBDeviceNumber(const std::string& value, int& number);
void addUSBDeviceRow(QueryData& results,
                     Row row,
                     const std::string& usb_address_value,
                     const std::string& usb_port_value);

} // namespace tables
} // namespace osquery
