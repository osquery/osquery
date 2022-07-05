/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/linux/smbios_utils.h>

namespace osquery {
namespace tables {

static const std::map<std::string, std::string> ProcessorTypeToFriendlyName = {
    {"3", "CPU"}, {"4", "MATH"}, {"5", "DSP"}, {"6", "GPU"}};

QueryData genCpuInfo(QueryContext& context) {
  QueryData results;
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Failed to discover SMBIOS entry point";
    return results;
  }

  parser.tables(([&results](size_t index,
                            const SMBStructHeader* hdr,
                            uint8_t* address,
                            uint8_t* textAddrs,
                            size_t size) {
    genSMBIOSProcessor(index, hdr, address, textAddrs, size, results);
  }));

  // Decorate table
  uint8_t deviceId = 0;
  for (auto& row : results) {
    auto currentProcessorId = row.find("processor_type");
    if (currentProcessorId == row.end()) {
      continue;
    }

    // `device_id` column is not part of the SMBios table.
    auto friendlyName =
        ProcessorTypeToFriendlyName.find(currentProcessorId->second);
    if (friendlyName != ProcessorTypeToFriendlyName.end()) {
      row["device_id"] = friendlyName->second + std::to_string(deviceId++);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
