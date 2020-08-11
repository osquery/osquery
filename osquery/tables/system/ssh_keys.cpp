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

namespace osquery {
namespace tables {

const std::string kSSHUserKeysDir = ".ssh/";

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
      r["encrypted"] =
          (keys_content.find("ENCRYPTED") != std::string::npos) ? "1" : "0";
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
