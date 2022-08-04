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
  std::int32_t device_id = 0;
  for (auto& row : results) {
    auto current_processor_id = row.find("processor_type");
    if (current_processor_id == row.end()) {
      continue;
    }

    // `device_id` column is not part of the SMBios table.
    auto friendly_name =
        kSMBIOSProcessorTypeFriendlyName.find(current_processor_id->second);
    if (friendly_name != kSMBIOSProcessorTypeFriendlyName.end()) {
      row["device_id"] = friendly_name->second + std::to_string(device_id++);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
