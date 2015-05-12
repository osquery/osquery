/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <vector>

#include <pwd.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history", ".zsh_history", ".zhistory", ".history",
};

void genShellHistoryForUser(const std::string& username,
                            const std::string& directory,
                            QueryData& results) {
  for (const auto& hfile : kShellHistoryFiles) {
    boost::filesystem::path history_file = directory;
    history_file /= hfile;

    std::string history_content;
    if (!readFile(history_file, history_content).ok()) {
      // Cannot read a specific history file.
      continue;
    }

    for (const auto& line : split(history_content, "\n")) {
      Row r;
      r["username"] = username;
      r["command"] = line;
      r["history_file"] = history_file.string();
      results.push_back(r);
    }
  }
}

QueryData genShellHistory(QueryContext& context) {
  QueryData results;

  QueryData users;
  if (!getuid()) {
    // No uid is available, attempt to select from all users.
    users = SQL::selectAllFrom("users");
  } else {
    // A uid is available, select only the home directory for this user.
    struct passwd* pwd = getpwuid(getuid());
    if (pwd != nullptr && pwd->pw_name != nullptr) {
      users = SQL::selectAllFrom(
          "users", "username", EQUALS, std::string(pwd->pw_name));
    }
  }

  // Iterate over each user
  for (const auto& row : users) {
    if (row.count("username") > 0 && row.count("directory") > 0) {
      genShellHistoryForUser(row.at("username"), row.at("directory"), results);
    }
  }

  return results;
}
}
}
