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
#include "osquery/tables/system/system_utils.h"

namespace xp = boost::xpressive;

#define DECLARE_TABLE_IMPLEMENTATION_shell_history
#include <generated/tables/tbl_shell_history_defs.hpp>

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history", ".zsh_history", ".zhistory", ".history", ".sh_history",
};

void genShellHistoryForUser(const std::string& uid,
                            const std::string& gid,
                            const std::string& directory,
                            QueryData& results) {
  auto dropper = DropPrivileges::get();
  if (!dropper->dropTo(uid, gid)) {
    VLOG(1) << "Cannot drop privileges to UID " << uid;
    return;
  }

  auto bash_timestamp_rx = xp::sregex::compile("^#(?P<timestamp>[0-9]+)$");
  auto zsh_timestamp_rx = xp::sregex::compile(
      "^: {0,10}(?P<timestamp>[0-9]{1,11}):[0-9]+;(?P<command>.*)$");

  for (const auto& hfile : kShellHistoryFiles) {
    boost::filesystem::path history_file = directory;
    history_file /= hfile;

    std::string history_content;
    if (!forensicReadFile(history_file, history_content).ok()) {
      // Cannot read a specific history file.
      continue;
    }

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
        r["command"] = line;
      }

      r["uid"] = uid;
      r["history_file"] = history_file.string();
      results.push_back(r);
    }
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
