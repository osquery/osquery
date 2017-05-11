/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/hash.h"

#include "osquery/core/signing.h"

namespace osquery {

Status verifySignature(const std::string& b64Pub,
                       const std::string& b64Sig,
                       const std::string& message) {
  Status ret;

  std::string pub_key = base64Decode(b64Pub);
  std::string sig = base64Decode(b64Sig);
  // Erase key the header
  pub_key.erase(0, 23);

  auto key = EC_KEY_new_by_curve_name(NID_secp256k1);
  auto pub_bytes_ref = reinterpret_cast<const unsigned char*>(pub_key.data());
  o2i_ECPublicKey(&key, &pub_bytes_ref, (long)pub_key.size());

  // Check that we can load the public key
  if (EC_KEY_check_key(key) != 1) {
    EC_KEY_free(key);
    return Status(1, "Unable to create public key");
  }
  const unsigned char* sig_ref = (unsigned char*)sig.c_str();
  // Load the signature
  ECDSA_SIG* signature =
      d2i_ECDSA_SIG(nullptr, &sig_ref, static_cast<long>(sig.size()));
  // Take the SHA256 of our message
  std::string h256 =
      hashFromBuffer(HASH_TYPE_SHA256, message.c_str(), message.size());
  // Convert it to a byte vector
  std::vector<unsigned char> byte_digest;
  boost::algorithm::unhex(h256, std::back_inserter(byte_digest));
  // Check that it matches
  if (ECDSA_do_verify(
          byte_digest.data(), (long)byte_digest.size(), signature, key) != 1) {
    ret = Status(1, "Verification Failed");
  }
  ECDSA_SIG_free(signature);
  // Garbage collection
  EC_KEY_free(key);
  return ret;
}
Status verifyStrictSignature(const std::string& b64Sig,
                             const std::string& message) {
  std::string strict_mode_key;
  getDatabaseValue(kPersistentSettings,
                   kStrictMode + "." + kStrictModePublicKey,
                   strict_mode_key);
  if (strict_mode_key.empty()) {
    return Status(0, "No strict mode key");
  }
  return verifySignature(strict_mode_key, b64Sig, message);
}

Status verifyQuerySignature(const std::string& b64Sig,
                            const std::string& query) {
  std::string strict_mode_key;
  std::string uuid_signing;
  std::string query_counter;
  std::string counter_mode;
  getDatabaseValue(kPersistentSettings,
                   kStrictMode + "." + kStrictModePublicKey,
                   strict_mode_key);
  getDatabaseValue(kPersistentSettings,
                   kStrictMode + "." + kStrictModeUUIDSigning,
                   uuid_signing);
  getDatabaseValue(
      kPersistentSettings, kStrictMode + ".query_counter", query_counter);
  getDatabaseValue(kPersistentSettings,
                   kStrictMode + "." + kStrictModeCounterMode,
                   counter_mode);
  if (strict_mode_key.empty()) {
    return Status(0, "No strict mode key");
  }

  Status s;
  std::string secure_query = query;
  if (uuid_signing == "true") {
    std::string uuid;
    osquery::getHostUUID(uuid);
    secure_query += "\n" + uuid;
  }
  if (counter_mode == "true") {
    secure_query += "\n" + query_counter;
  }
  s = verifySignature(strict_mode_key, b64Sig, secure_query);

  // Don't increment the counter if the verification fails
  if (s.ok() && counter_mode == "true") {
    unsigned long counter;
    safeStrtoul(query_counter, 10, counter);
    ++counter;
    setDatabaseValue(kPersistentSettings,
                     kStrictMode + ".query_counter",
                     std::to_string(counter));
  }
  return s;
}

bool doesQueryRequireSignature(const std::string& query) {
  std::set<std::string> protected_tables;
  std::vector<std::string> tables;
  {
    std::string db_protect;
    getDatabaseValue(kPersistentSettings,
                     kStrictMode + "." + kStrictModeProtectedTables,
                     db_protect);
    std::vector<std::string> protect_vec = split(db_protect, ",");
    for (const auto& table : protect_vec) {
      protected_tables.insert(table);
    }
  }
  Status s = getQueryTables(query, tables);
  // If for some reason we can't determine these tables, fail closed and
  // require a signature
  if (!s.ok()) {
    return true;
  }
  for (const auto& table : tables) {
    if (protected_tables.count(table) > 0) {
      return true;
    }
  }
  return false;
}
}