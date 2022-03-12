/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

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

  return results;
}

} // namespace tables
} // namespace osquery
