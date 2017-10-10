/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/posix/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHKnownHostskeys = {".ssh/known_hosts"};

void genSSHkeysForHosts(const std::string& uid,
                        const std::string& gid,
                        const std::string& directory,
                        QueryData& results) {
  auto dropper = DropPrivileges::get();
  unsigned long int _uid = 0;
  unsigned long int _gid = 0;
  if (!safeStrtoul(uid, 10, _uid).ok() || !safeStrtoul(gid, 10, _gid).ok() ||
      !dropper->dropTo(static_cast<uid_t>(_uid), static_cast<gid_t>(_gid))) {
    VLOG(1) << "Cannot drop privileges to UID " << uid;
    return;
  }

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

QueryData getKnownHostsKeys(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeysForHosts(uid->second, gid->second, directory->second, results);
    }
  }

  return results;
}
}
}
