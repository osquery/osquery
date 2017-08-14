/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <unistd.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/sql.h>

extern "C" {
#include <libcryptsetup.h>
}

namespace osquery {
namespace tables {

void genFDEStatusForBlockDevice(const std::string &name,
                                const std::string &uuid,
                                QueryData &results) {
  Row r;
  r["name"] = name;
  r["uuid"] = uuid;

  struct crypt_device* cd = nullptr;
  struct crypt_active_device cad;
  crypt_status_info ci;
  std::string type;
  std::string cipher;
  std::string cipher_mode;

  ci = crypt_status(cd, name.c_str());
  switch (ci) {
  case CRYPT_ACTIVE:
  case CRYPT_BUSY: {
    r["encrypted"] = "1";

    int crypt_init;
#if defined(CENTOS_CENTOS6) || defined(RHEL_RHEL6) || \
    defined(SCIENTIFIC_SCIENTIFIC6)
    crypt_init = crypt_init_by_name(&cd, name.c_str());
#else
    crypt_init = crypt_init_by_name_and_header(&cd, name.c_str(), nullptr);
#endif

    if (crypt_init < 0) {
      VLOG(1) << "Unable to initialize crypt device for " << name;
      break;
    }

    type = crypt_get_type(cd);
    if (crypt_get_active_device(cd, name.c_str(), &cad) < 0) {
      VLOG(1) << "Unable to get active device for " << name;
      break;
    }
    cipher = crypt_get_cipher(cd);
    cipher_mode = crypt_get_cipher_mode(cd);
    r["type"] = type + "-" + cipher + "-" + cipher_mode;
    break;
  }

  default:
    r["encrypted"] = "0";
  }

  if (cd != nullptr) {
    crypt_free(cd);
  }
  results.push_back(r);
}

QueryData genFDEStatus(QueryContext &context) {
  QueryData results;

  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, disk encryption status not available";
    return results;
  }

  auto block_devices = SQL::selectAllFrom("block_devices");
  for (const auto &row : block_devices) {
    const auto name = (row.count("name") > 0) ? row.at("name") : "";
    const auto uuid = (row.count("uuid") > 0) ? row.at("uuid") : "";
    genFDEStatusForBlockDevice(name, uuid, results);
  }
  return results;
}
}
}
