/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unistd.h>

#include <algorithm>
#include <set>
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

// Helper class to track of device parents and ensure that
// devices are queried no more than once.
class DeviceParentIndex {
  std::set<std::string> unresolved;
  std::set<std::string> resolved;

 public:
  void requestDevice(const std::string& name) {
    if (!resolved.count(name)) {
      unresolved.insert(name);
    }
  }

  void addDevice(const std::string& name) {
    resolved.insert(name);
    unresolved.erase(name);
  }

  bool hasUnresolved() const {
    return unresolved.size() > 0;
  }

  std::string nextUnresolved() const {
    return *unresolved.cbegin();
  }
};

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
    // works because the devices have been sorted by depth.
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

// Sorts devices by depth such that parent devices are ordered before child
// devices.
static void sortDevicesByDepth(QueryData& block_devices) {
  std::map<std::string, const Row*> devices_by_name;
  std::map<const Row*, int> depth;
  for (const auto& row : block_devices) {
    if (row.count("name")) {
      devices_by_name[row.at("name")] = &row;
      depth[&row] = -1;
    }
  }

  for (auto& pair : depth) {
    const Row* row = pair.first;
    pair.second = -1;
    while (row) {
      pair.second++;
      const Row* next_row = nullptr;
      if (row->count("parent")) {
        const auto& parent_name = row->at("parent");
        if (devices_by_name.count(parent_name)) {
          next_row = devices_by_name.at(parent_name);
        }
      }
      row = next_row;
    }
  }

  std::sort(block_devices.begin(),
            block_devices.end(),
            [&](const Row& a, const Row& b) { return depth[&a] < depth[&b]; });
}

QueryData genFDEStatus(QueryContext& context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  bool runSelectAll(true);
  QueryData block_devices;

  if (auto constraint_it = context.constraints.find("name");
      constraint_it != context.constraints.end()) {
    DeviceParentIndex device_parent_index;
    const auto& constraints = constraint_it->second;
    for (const auto& name : constraints.getAll(EQUALS)) {
      runSelectAll = false;
      device_parent_index.requestDevice(name);
    }

    while (device_parent_index.hasUnresolved()) {
      const auto name = device_parent_index.nextUnresolved();
      const auto data =
          SQL::selectAllFrom("block_devices", "name", EQUALS, name);
      if (!data.size()) {
        VLOG(1) << "Failed to find name " << name << " in table block_devices";
        break;
      }

      for (const auto& row : data) {
        block_devices.push_back(row);
        if (!row.count("name")) {
          // Should never happen
          VLOG(1) << "Row in block_devices has no name, expecting " << name;
          break;
        }
        device_parent_index.addDevice(row.at("name"));
        if (row.count("parent")) {
          device_parent_index.requestDevice(row.at("parent"));
        }
      }
    }
  }

  if (runSelectAll) {
    for (const auto& row : SQL::selectAllFrom("block_devices")) {
      block_devices.push_back(row);
    }
  }

  sortDevicesByDepth(block_devices);

  std::map<std::string, Row> encrypted_rows;

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
