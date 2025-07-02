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
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/linux/block_device_enumeration.h>

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
void genFDEStatusForBlockDevice(const BlockDevice& block_device,
                                std::set<BlockDevice>& block_devices,
                                std::map<std::string, Row>& encryption_status) {
  Row r;
  r["name"] = block_device.name;
  r["uuid"] = block_device.uuid;

  struct crypt_device* cd = nullptr;
  auto ci = crypt_status(cd, block_device.name.c_str());

  switch (ci) {
  case CRYPT_ACTIVE:
  case CRYPT_BUSY: {
    r["encrypted"] = "1";
    r["encryption_status"] = kEncryptionStatusEncrypted;
    r["type"] = "";

    auto crypt_init =
        crypt_init_by_name_and_header(&cd, block_device.name.c_str(), nullptr);
    if (crypt_init < 0) {
      VLOG(1) << "Unable to initialize crypt device for " << block_device.name;
      break;
    }

    struct crypt_active_device cad;
    if (crypt_get_active_device(cd, block_device.name.c_str(), &cad) < 0) {
      VLOG(1) << "Unable to get active device for " << block_device.name;
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
  default:
    r["encryption_status"] = kEncryptionStatusNotEncrypted;
    r["encrypted"] = "0";
    r["type"] = "";

    // Set crypt status from parent block device.
    if (!block_device.parent.empty()) {
      // Since `genFDEStatusForBlockDevice` is recursive, ensure no duplicates.
      if (!encryption_status.count(block_device.parent)) {
        if (auto parent = block_devices.find(block_device.parent);
            parent != block_devices.end()) {
          genFDEStatusForBlockDevice(*parent, block_devices, encryption_status);
        }
      }

      auto parent_row = encryption_status[block_device.parent];
      r["encryption_status"] = parent_row["encryption_status"];
      r["encrypted"] = parent_row["encrypted"];
      r["type"] = parent_row["type"];
    }
  }

  if (cd != nullptr) {
    crypt_free(cd);
  }

  encryption_status[r["name"]] = r;
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  std::map<std::string, Row> encryption_status;
  auto query_context = context.constraints["name"].getAll(EQUALS);
  auto block_devices = enumerateBlockDevices(query_context, true);

  for (const auto& block_device : block_devices) {
    // Since `genFDEStatusForBlockDevice` is recursive, ensure no duplicates.
    if (!encryption_status.count(block_device.name)) {
      genFDEStatusForBlockDevice(
          block_device, block_devices, encryption_status);
    }

    results.push_back(encryption_status[block_device.name]);
  }

  return results;
}
} // namespace tables
} // namespace osquery
