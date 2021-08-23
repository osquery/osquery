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

void genFDEStatusForBlockDevice(const std::string& name,
                                const std::string& uuid,
                                const std::string& parent_name,
                                std::map<std::string, Row>& encrypted_rows,
                                QueryData& results) {
  Row r;
  r["name"] = name;
  r["uuid"] = uuid;

  struct crypt_device* cd = nullptr;
  auto ci = crypt_status(cd, name.c_str());

  switch (ci) {
  case CRYPT_ACTIVE:
  case CRYPT_BUSY: {
    r["encrypted"] = "1";
    r["encryption_status"] = kEncryptionStatusEncrypted;

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
    encrypted_rows[name] = r;
    break;
  }

    // If there's no good crypt status, check to see if we've already
    // defined the parent_name. If so, inherit data from there. This
    // works because the `SQL::selectAllFrom("block_devices")` is
    // ordered enough. If that order proves inadequate, we may need
    // to explicitly sort it.
  default:
    if (encrypted_rows.count(parent_name)) {
      auto parent_row = encrypted_rows[parent_name];
      r["encryption_status"] = kEncryptionStatusEncrypted;
      r["encrypted"] = "1";
      r["type"] = parent_row["type"];
    } else {
      r["encryption_status"] = kEncryptionStatusNotEncrypted;
      r["encrypted"] = "0";
    }
  }

  if (cd != nullptr) {
    crypt_free(cd);
  }
  results.push_back(r);
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  std::map<std::string, Row> encrypted_rows;

  bool runSelectAll(true);
  QueryData block_devices;

  if (auto constraint_it = context.constraints.find("name");
      constraint_it != context.constraints.end()) {
    const auto& constraints = constraint_it->second;
    for (const auto& name : constraints.getAll(EQUALS)) {
      runSelectAll = false;

      auto data = SQL::selectAllFrom("block_devices", "name", EQUALS, name);
      for (const auto& row : data) {
        block_devices.push_back(row);
      }
    }
  }

  if (runSelectAll) {
    block_devices = SQL::selectAllFrom("block_devices");
  }

  for (const auto& row : block_devices) {
    const auto name = (row.count("name") > 0) ? row.at("name") : "";
    const auto uuid = (row.count("uuid") > 0) ? row.at("uuid") : "";
    const auto parent_name = (row.count("parent") > 0 ? row.at("parent") : "");
    genFDEStatusForBlockDevice(
        name, uuid, parent_name, encrypted_rows, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
