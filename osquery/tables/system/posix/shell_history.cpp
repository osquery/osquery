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

#include <boost/xpressive/xpressive.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/posix/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/posix/shell_history.h"
#include "osquery/tables/system/system_utils.h"

namespace xp = boost::xpressive;

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history", ".zsh_history", ".zhistory", ".history", ".sh_history",
};

void genShellHistoryFromFile(const std::string& uid,
                             const boost::filesystem::path& history_file,
                             QueryData& results) {
  std::string history_content;
  if (forensicReadFile(history_file, history_content).ok()) {
    auto bash_timestamp_rx = xp::sregex::compile("^#(?P<timestamp>[0-9]+)$");
    auto zsh_timestamp_rx = xp::sregex::compile(
        "^: {0,10}(?P<timestamp>[0-9]{1,11}):[0-9]+;(?P<command>.*)$");

    std::string prev_bash_timestamp;
    for (const auto& line : split(history_content, "\n")) {
      xp::smatch bash_timestamp_matches;
      xp::smatch zsh_timestamp_matches;

      if (prev_bash_timestamp.empty() &&
          xp::regex_search(line, bash_timestamp_matches, bash_timestamp_rx)) {
        prev_bash_timestamp = bash_timestamp_matches["timestamp"];
        continue;
      }

      Row r;

      if (!prev_bash_timestamp.empty()) {
        r["time"] = INTEGER(prev_bash_timestamp);
        r["command"] = line;
        prev_bash_timestamp.clear();
      } else if (xp::regex_search(
                     line, zsh_timestamp_matches, zsh_timestamp_rx)) {
        r["time"] = INTEGER(zsh_timestamp_matches["timestamp"]);
        r["command"] = zsh_timestamp_matches["command"];
      } else {
        r["time"] = INTEGER(0);
        r["command"] = line;
      }

      r["uid"] = uid;
      r["history_file"] = history_file.string();
      results.push_back(r);
    }
  }
}

void genShellHistoryForUser(const std::string& uid,
                            const std::string& gid,
                            const std::string& directory,
                            QueryData& results) {
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo(uid, gid)) {
    VLOG(1) << "Cannot drop privileges to UID " << uid;
    return;
  }

  for (const auto& hfile : kShellHistoryFiles) {
    boost::filesystem::path history_file = directory;
    history_file /= hfile;
    genShellHistoryFromFile(uid, history_file, results);
  }
}

QueryData genShellHistory(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto dir = row.find("directory");
    if (uid != row.end() && gid != row.end() && dir != row.end()) {
      genShellHistoryForUser(uid->second, gid->second, dir->second, results);
    }
  }

  return results;
}
}
}
