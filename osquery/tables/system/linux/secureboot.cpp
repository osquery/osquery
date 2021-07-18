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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>

namespace osquery {
namespace tables {

// Linux directory for efi vars
const std::string efivarsPath = "/sys/firmware/efi/vars/";

int readBoolEfiVar(std::string guid, std::string name) {
  const std::string efivar = efivarsPath + name + '-' + guid;

  BYTE data;

  if (!readFile(path, data).ok()) {
    TLOG << "Cannot read efivar file : " << path
      return -1;
  }

  return -1;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;

  Row r;
  r["secure_boot"] = readBoolEfiVar(kBootGUID, kSecureBootName);
  r["setup_mode"] = readBoolEfiVar(kBootGUID, kSetupModeName);

  results.push_back(r);
  return results;
}
} // namespace tables
} // namespace osquery
