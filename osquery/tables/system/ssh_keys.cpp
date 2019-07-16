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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>

namespace osquery {
namespace tables {

const std::string kSSHUserKeysDir = ".ssh/";
const std::string kEd25519Header = "-----BEGIN OPENSSH PRIVATE KEY-----\n";

// The first bytes of an OpenSSH key are |key type|length of cipher name|cipher
// name| so all unencrypted ed25519 keys should start with the value below
// (encoded in base64) This magic string is
//  6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00 00 00 00 04 6e 6f 6e 65
// |--------------------------------------------|-----------|----------|
// | o  p  e  n  s  s  h  -  k  e  y  -  v  1 \0|          4| n  o  n e|
//
const std::string kEd25519UnencryptedPrefix = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";

bool isEncrypted(std::string& keys_content) {
  if (boost::starts_with(keys_content, kEd25519Header)) {
    const std::string prefix = keys_content.substr(
        kEd25519Header.size(), kEd25519UnencryptedPrefix.size());
    return prefix != kEd25519UnencryptedPrefix;
  }
  return keys_content.find("ENCRYPTED") != std::string::npos;
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

    if (keys_content.find("PRIVATE KEY") != std::string::npos) {
      // File is private key, create record for it
      Row r;
      r["uid"] = uid;
      r["path"] = kfile;
      r["encrypted"] = isEncrypted(keys_content) ? "1" : "0";
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
