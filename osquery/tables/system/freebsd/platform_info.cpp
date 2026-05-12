/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD platform_info: pull BIOS/firmware fields from kenv(2).  The
 * kernel parses the SMBIOS table at boot and exposes the relevant
 * strings under "smbios.bios.*"; reading them via kenv(2) avoids
 * mapping /dev/mem and re-parsing the table ourselves.
 */

#include <kenv.h>
#include <sys/types.h>

#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/info/firmware.h>

namespace osquery {
namespace tables {

namespace {

std::string kenvGet(const char* name) {
  char value[KENV_MVALLEN + 1] = {0};
  if (kenv(KENV_GET, name, value, sizeof(value) - 1) <= 0) {
    return "";
  }
  return std::string(value);
}

} // namespace

QueryData genPlatformInfo(QueryContext& context) {
  Row r;
  r["vendor"] = kenvGet("smbios.bios.vendor");
  r["version"] = kenvGet("smbios.bios.version");
  r["date"] = kenvGet("smbios.bios.reldate");
  r["revision"] = kenvGet("smbios.bios.revision");
  r["extra"] = "";

  auto fw = getFirmwareKind();
  if (fw.has_value()) {
    r["firmware_type"] = getFirmwareKindDescription(fw.value());
  } else {
    r["firmware_type"] = "unknown";
  }

  // If every column we tried is empty the host is unlikely to have
  // SMBIOS at all (jail, VM without DMI tables, ...).  Return an
  // empty result set rather than a row of empty strings so callers
  // can distinguish "no data" from "all blanks".
  if (r["vendor"].empty() && r["version"].empty() && r["date"].empty() &&
      r["revision"].empty() && r["firmware_type"] == "unknown") {
    return {};
  }

  return {r};
}

} // namespace tables
} // namespace osquery
