/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unistd.h>

#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/join.h>

extern "C" {
#include <libcryptsetup.h>
}

// FIXME: Add enum generation for tables and remove following code
// Copy of values in disk_encryption.mm
const std::string kEncryptionStatusEncrypted = "encrypted";
const std::string kEncryptionStatusUndefined = "undefined";
const std::string kEncryptionStatusNotEncrypted = "not encrypted";

namespace osquery {
namespace tables {
// Calls to block_devices is done here to allow genFDEStatusForBlockDevice
// to query parent block devices for crypt status after initial queries.
void queryBlockDevice(const bool& runSelectAll,
                      const std::string& device,
                      std::map<std::string, Row>& block_devices) {
  // There's protection around calls, but this ensures no duplicates.
  if ((runSelectAll && block_devices.size() > 0) ||
      (!runSelectAll && block_devices.count(device) > 0)) {
    return;
  }

  auto data = runSelectAll
                  ? SQL::selectAllFrom("block_devices")
                  : SQL::selectAllFrom("block_devices", "name", EQUALS, device);
  for (const auto& row : data) {
    if (row.count("name") > 0) {
      block_devices[row.at("name")] = row;
    }
  }
}

void genFDEStatusForBlockDevice(const bool& runSelectAll,
                                const Row& block_device,
                                std::map<std::string, Row>& block_devices,
                                std::map<std::string, Row>& encrypted_rows) {
  const auto name = block_device.at("name");
  const auto parent_name =
      (block_device.count("parent") > 0 ? block_device.at("parent") : "");
  Row r;
  r["name"] = name;
  r["uuid"] = (block_device.count("uuid") > 0) ? block_device.at("uuid") : "";

  struct crypt_device* cd = nullptr;
  auto ci = crypt_status(cd, name.c_str());

  switch (ci) {
  case CRYPT_ACTIVE:
  case CRYPT_BUSY: {
    r["encrypted"] = "1";
    r["encryption_status"] = kEncryptionStatusEncrypted;
    r["type"] = "";

    auto crypt_init = crypt_init_by_name_and_header(&cd, name.c_str(), nullptr);
    if (crypt_init < 0) {
      VLOG(1) << "Unable to initialize crypt device for " << name;
      break;
    }

    struct crypt_active_device cad;
    if (crypt_get_active_device(cd, name.c_str(), &cad) < 0) {
      VLOG(1) << "Unable to get active device for " << name;
      break;
    }

    // Construct the "type" with the cipher and mode too.
    std::vector<std::string> items;

    auto ctype = crypt_get_type(cd);
    if (ctype != nullptr) {
      items.push_back(ctype);
    }

    auto ccipher = crypt_get_cipher(cd);
    if (ccipher != nullptr) {
      items.push_back(ccipher);
    }

    auto ccipher_mode = crypt_get_cipher_mode(cd);
    if (ccipher_mode != nullptr) {
      items.push_back(ccipher_mode);
    }

    r["type"] = osquery::join(items, "-");
    break;
  }
  // If there's no good crypt status, use the parent device's crypt status.
  default:
    // Step through each parent once until we either reach
    // the root device, or a device with valid encryption.
    if (!parent_name.empty()) {
      if (!encrypted_rows.count(parent_name)) {
        if (!block_devices.count(parent_name)) {
          queryBlockDevice(runSelectAll, parent_name, block_devices);
        }

        genFDEStatusForBlockDevice(runSelectAll,
                                   block_devices[parent_name],
                                   block_devices,
                                   encrypted_rows);
      }

      // The recursive calls return back, and each child
      // device takes the encryption values of their parent.
      auto parent_row = encrypted_rows[parent_name];
      r["encryption_status"] = parent_row["encryption_status"];
      r["encrypted"] = parent_row["encrypted"];
      r["type"] = parent_row["type"];
    } else {
      r["encryption_status"] = kEncryptionStatusNotEncrypted;
      r["encrypted"] = "0";
      r["type"] = "";
    }
  }

  encrypted_rows[name] = r;

  if (cd != nullptr) {
    crypt_free(cd);
  }
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  bool runSelectAll(true);
  std::vector<std::string> queried_devices;
  std::map<std::string, Row> block_devices;
  std::map<std::string, Row> encrypted_rows;

  if (auto constraint_it = context.constraints.find("name");
      constraint_it != context.constraints.end()) {
    const auto& constraints = constraint_it->second;
    for (const auto& device : constraints.getAll(EQUALS)) {
      runSelectAll = false;

      if (!block_devices.count(device)) {
        queryBlockDevice(runSelectAll, device, block_devices);
        queried_devices.push_back(device);
      }
    }
  }

  if (runSelectAll) {
    queryBlockDevice(runSelectAll, "", block_devices);
  }

  // Generate and add an encryption row result for each queried block device.
  for (const auto& pair : block_devices) {
    if (!encrypted_rows.count(pair.first)) {
      genFDEStatusForBlockDevice(
          runSelectAll, pair.second, block_devices, encrypted_rows);
    }

    if (queried_devices.empty() ||
        std::count(
            queried_devices.begin(), queried_devices.end(), pair.first)) {
      results.push_back(encrypted_rows[pair.first]);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
