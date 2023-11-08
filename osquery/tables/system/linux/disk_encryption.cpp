/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unistd.h>

#include <filesystem>
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
// Follow a block device sysfs symlink and enumerate over the possible parents.
std::vector<std::string> enumerateParentsForBlockDevice(
    std::filesystem::path block_device_path) {
  std::vector<std::string> parents;

  // Follow the block device symlink to the device.
  if (std::filesystem::is_symlink(block_device_path)) {
    auto symlink = std::filesystem::read_symlink(block_device_path);
    auto device_path = std::filesystem::canonical(symlink);
    auto parent = device_path.parent_path().filename().string();
    device_path /= "slaves";

    // Check if slaves directory exists and enumerate the parents if it does.
    if (std::filesystem::exists(device_path)) {
      for (const auto& slave_device :
           std::filesystem::directory_iterator(device_path)) {
        parents.push_back(slave_device.path().filename().string());
      }
    }

    // If no slave directory exists, or no entries are in the directory, then
    // set the parent from the parent directory.
    if (parents.size() == 0 && parent != "block") {
      parents.push_back(parent);
    }
  }

  return parents;
}

void genFDEStatusForBlockDevice(
    const std::string& name,
    std::map<std::string, std::filesystem::path>& block_devices,
    std::map<std::string, Row>& encryption_status) {
  Row r;
  r["name"] = name;

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
  default:
    r["encryption_status"] = kEncryptionStatusNotEncrypted;
    r["encrypted"] = "0";
    r["type"] = "";

    // If there's no good crypt status, then walk up the device tree until we
    // either reach the root, or we find good crypt status to inherit.
    auto parents = enumerateParentsForBlockDevice(block_devices[name]);
    for (const auto& parent : parents) {
      const auto parent_name = "/dev/" + parent;

      // Generate the parent status if it doesn't exist yet.
      if (!encryption_status.count(parent_name)) {
        genFDEStatusForBlockDevice(
            parent_name, block_devices, encryption_status);
      }

      // Set valid crypt status from parent block device.
      auto parent_row = encryption_status[parent_name];
      if (parent_row["encrypted"] == "1") {
        r["encryption_status"] = parent_row["encryption_status"];
        r["encrypted"] = parent_row["encrypted"];
        r["type"] = parent_row["type"];
        break;
      }
    }
  }

  if (cd != nullptr) {
    crypt_free(cd);
  }

  encryption_status[name] = r;
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  // We want to cache the block devices and the encryption status, so that we
  // can recursively establish the device tree encryption status and inherit
  // from parents.
  std::map<std::string, std::filesystem::path> block_devices;
  std::map<std::string, Row> encryption_status;

  // For Linux block device encryption status, we can simply walk sysfs.
  // [See](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=edfaa7c36574f1bf09c65ad602412db9da5f96bf)
  std::filesystem::path block_device_dir = "/sys/class/block";
  std::filesystem::current_path(block_device_dir);

  // Cache the list of block devices and their sysfs class path. This is
  // lightweight, and there needs to be a way to access the parent device when
  // setting encryption status, so enumerate all block devices without checking
  // query context.
  for (const auto& block_device :
       std::filesystem::directory_iterator(block_device_dir)) {
    auto path = block_device.path();
    auto name = "/dev/" + path.filename().string();
    block_devices[name] = path;
  }

  auto query_context = context.constraints.find("name")->second.getAll(EQUALS);

  for (const auto& pair : block_devices) {
    // Only generate encryption status for devices in the query context.
    if (!query_context.empty() &&
        std::find(query_context.begin(), query_context.end(), pair.first) ==
            query_context.end()) {
      continue;
    }

    // Since `genFDEStatusForBlockDevice` is recursive, ensure no duplicates.
    if (!encryption_status.count(pair.first)) {
      genFDEStatusForBlockDevice(pair.first, block_devices, encryption_status);
    }

    results.push_back(encryption_status[pair.first]);
  }

  return results;
}
} // namespace tables
} // namespace osquery
