/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/system/posix/known_hosts.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/system.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHKnownHostskeys = {".ssh/known_hosts"};

namespace impl {

void genSSHkeysForHosts(const std::string& uid,
                        const std::string& gid,
                        const std::string& directory,
                        QueryData& results) {
  for (const auto& kfile : kSSHKnownHostskeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;

    std::string keys_content;
    if (!forensicReadFile(keys_file, keys_content).ok()) {
      // Cannot read a specific keys file.
      continue;
    }

    for (const auto& line : split(keys_content, "\n")) {
      if (!line.empty() && line[0] != '#') {
        Row r = {{"uid", uid}, {"key", line}, {"key_file", keys_file.string()}};
        results.push_back(r);
      }
    }
  }
}

} // namespace impl

QueryData getKnownHostsKeys(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      impl::genSSHkeysForHosts(
          uid->second, gid->second, directory->second, results);
    }
  }

  return results;
}
}
}
