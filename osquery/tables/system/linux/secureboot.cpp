/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>

namespace osquery {
namespace tables {

// Linux has 2 places efivars can be accessed:
//   /sys/firmware/efi/efivars -- Single file, world readable
//   /sys/firmware/efi/vars    -- Split into attributes and data, only root
//   readable
//
// There's not much documentation about the provenance of these two
// interfaces. While the `vars` directory is more usable (having a
// split data from attributes), the benefit of not requiring root
// outweighs that.
const std::string efivarsDir = "/sys/firmware/efi/efivars/";

int readBoolEfiVar(std::string guid, std::string name) {
  const std::string efivarPath = efivarsDir + name + '-' + guid;

  // The first 4 bytes of efivars are attribute data, we don't need
  // that data here, so we can just ignore it. The 5th byte is a
  // boolean representation.
  std::string efiData;
  if (!readFile(efivarPath, efiData, 5).ok()) {
    // FIXME: this is likely to mean it's unsupported by the
    // kernel/boot/whatever. Probably don't log and return null?
    TLOG << "Cannot read efivar file : " << efivarPath;
    return -1;
  }

  if (efiData.length() != 5) {
    TLOG << "Under read on efivar file : " << efivarPath;
    return -1;
  }

  auto val = (int)(unsigned char)(efiData.back());

  switch (val) {
  case 0:
    return 0;
  case 1:
    return 1;
  }

  return -1;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;
  Row r;

  // There's a kernel rate limit on non-root reads to the EFI
  // filesystem of 100 reads per second. We could consider adding a
  // sleep, as a means to a rate limit (this is what the efivar tool
  // does), but this seems unlikely to be an issue in normal osquery
  // use. So we do nothing, aside from note it here.
  r["secure_boot"] = INTEGER(readBoolEfiVar(kEFIBootGUID, kEFISecureBootName));
  r["setup_mode"] = INTEGER(readBoolEfiVar(kEFIBootGUID, kEFISetupModeName));

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
