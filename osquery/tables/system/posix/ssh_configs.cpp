/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/posix/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace osquery {
namespace tables {

const std::string kUserSSHConfig = ".ssh/config";
const std::string kSystemwideSSHConfig = "/etc/ssh/ssh_config";

void genSSHConfig(const std::string& uid,
                  const std::string& gid,
                  const boost::filesystem::path& filepath,
                  QueryData& results) {
  std::string ssh_config_content;
  if (!forensicReadFile(filepath, ssh_config_content).ok()) {
    // Cannot read a specific ssh_config file.
    return;
  }
  // the ssh_config file consists of a number of host or match
  // blocks containing newline-separated options for each
  // block; a block is defined as everything following a
  // host or match keyword, until the next host or match
  // keyword, else EOF
  std::string block;
  for (auto& line : split(ssh_config_content, "\n")) {
    boost::trim(line);
    boost::to_lower(line);
    if (!line.empty() && line[0] != '#') {
      if (boost::starts_with(line, "host ") ||
          boost::starts_with(line, "match ")) {
        block = line;
      } else {
        Row r = {{"uid", uid},
                 {"block", block},
                 {"option", line},
                 {"ssh_config_file", filepath.string()}};
        results.push_back(r);
      }
    }
  }
}
void genSSHConfigForUser(const std::string& uid,
                         const std::string& gid,
                         const std::string& directory,
                         QueryData& results) {
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo(uid, gid)) {
    VLOG(1) << "Cannot drop privileges to UID " << uid;
    return;
  }

  boost::filesystem::path ssh_config_file = directory;
  ssh_config_file /= kUserSSHConfig;

  genSSHConfig(uid, gid, ssh_config_file, results);
}
QueryData getSSHConfigs(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHConfigForUser(uid->second, gid->second, directory->second, results);
    }
  }
  genSSHConfig("0", "0", kSystemwideSSHConfig, results);
  return results;
}
} // namespace tables
} // namespace osquery
