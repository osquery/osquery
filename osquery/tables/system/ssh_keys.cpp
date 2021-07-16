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
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

const std::string kSSHUserKeysDir = ".ssh/";

void genSSHkeyForHosts(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
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
    auto s = forensicReadFile(kfile, keys_content, false, false);
    if (!s.ok()) {
      // Cannot read a specific keys file.
      logger.log(google::GLOG_WARNING, s.getMessage());
      logger.vlog(1, s.getMessage());
      continue;
    }

    if (keys_content.find("PRIVATE KEY") != std::string::npos) {
      // File is private key, create record for it
      Row r;
      r["pid_with_namespace"] = "0";
      r["uid"] = uid;
      r["path"] = kfile;
      r["encrypted"] =
          (keys_content.find("ENCRYPTED") != std::string::npos) ? "1" : "0";
      results.push_back(r);
    }
  }
}

QueryData getUserSshKeysImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeyForHosts(
          uid->second, gid->second, directory->second, results, logger);
    }
  }

  return results;
}

QueryData getUserSshKeys(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "user_ssh_keys", getUserSshKeysImpl);
  } else {
    GLOGLogger logger;
    return getUserSshKeysImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
