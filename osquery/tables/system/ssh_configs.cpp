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

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/system/system.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kUserSshConfig = ".ssh/config";
const std::string kSystemwideSshConfig = "/etc/ssh/ssh_config";
const std::string kWindowsSystemwideSshConfig =
    "\\ProgramData\\ssh\\ssh_config";

void genSshConfig(const std::string& uid,
                  const std::string& gid,
                  const fs::path& filepath,
                  QueryData& results) {
  std::string ssh_config_content;
  if (!forensicReadFile(filepath, ssh_config_content).ok()) {
    VLOG(1) << "Cannot read ssh_config file " << filepath;
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
    if (line.empty() || line[0] == '#') {
      continue;
    }
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
void genSshConfigForUser(const std::string& uid,
                         const std::string& gid,
                         const std::string& directory,
                         QueryData& results) {
  boost::filesystem::path ssh_config_file = directory;
  ssh_config_file /= kUserSshConfig;

  genSshConfig(uid, gid, ssh_config_file, results);
}
QueryData getSshConfigs(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSshConfigForUser(uid->second, gid->second, directory->second, results);
    }
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    genSshConfig("0", "0", kWindowsSystemwideSshConfig, results);
  } else {
    genSshConfig("0", "0", kSystemwideSshConfig, results);
  }
  return results;
}
} // namespace tables
} // namespace osquery
