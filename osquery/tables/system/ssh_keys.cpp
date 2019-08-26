/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/log ger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace osquery {
namespace tables {

// parsePrivateKey returns true iff the key is valid
bool parsePrivateKey(std::string& keys_content,
                     int* key_type,
                     bool* is_encrypted) {
  BIO* bio_stream = BIO_new(BIO_s_mem());
  BIO_write(bio_stream, keys_content.c_str(), keys_content.size());
  if (bio_stream == nullptr) {
    return false;
  }

  // PEM_read_bio_PrivateKey calls passwordCallback
  // if the private key is encrypted. We don't care what the key is;
  // only whether or not it's encrypted.
  static bool encrypted = false;
  auto passwordCallback = [](char*, int, int, void*) {
    encrypted = true;
    return -1; // let openssl know that the passwordCallback failed
  };

  EVP_PKEY* pkey;
  pkey =
      PEM_read_bio_PrivateKey(bio_stream, nullptr, passwordCallback, nullptr);
  *is_encrypted = encrypted;
  scope_guard::create([=]() {
    BIO_free(bio_stream);
    EVP_PKEY_free(pkey);
  });

  if (pkey == nullptr) {
    if (encrypted) {
      *key_type = EVP_PKEY_NONE;
      encrypted = false;
      return true;
    }
    return false;
  }

  *key_type = EVP_PKEY_base_id(pkey);
  return true;
}

std::string keyTypeAsString(int key_type) {
  switch (key_type) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:
    return "rsa";
  case EVP_PKEY_DSA:
  case EVP_PKEY_DSA1:
  case EVP_PKEY_DSA2:
  case EVP_PKEY_DSA3:
  case EVP_PKEY_DSA4:
    return "dsa";
  case EVP_PKEY_DH:
  case EVP_PKEY_DHX:
    return "dh";
  case EVP_PKEY_EC:
    return "ec";
  case EVP_PKEY_HMAC:
    return "hmac";
  case EVP_PKEY_CMAC:
    return "cmac";
  default:
    return "";
  }
}

void genSSHkeyForHosts(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results) {
  // Get list of files in directory
  boost::filesystem::path keys_dir = directory;
  keys_dir /= kSSHUserKeysDir;
  std::vector<std::string> files_list;
  auto status = listFilesInDirectory(keys_dir, files_list, false);
  if (!status.ok()) {
    return;
  }

  // Go through each file
  for (const auto& kfile : files_list) {
    std::string keys_content;
    if (!forensicReadFile(kfile, keys_content).ok()) {
      // Cannot read a specific keys file.
      continue;
    }
    int key_type;
    bool encrypted;
    bool parsed = parsePrivateKey(keys_content, &key_type, &encrypted);
    if (parsed) {
      Row r;
      r["uid"] = uid;
      r["path"] = kfile;
      r["encrypted"] = encrypted ? "1" : "0";
      r["key_type"] = keyTypeAsString(key_type);
      results.push_back(r);
    }
  }
}

QueryData getUserSshKeys(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeyForHosts(uid->second, gid->second, directory->second, results);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
