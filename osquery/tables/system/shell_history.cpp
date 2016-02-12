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
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history", ".zsh_history", ".zhistory", ".history", ".sh_history",
};

void genShellHistoryForUser(const std::string& uid,
                            const std::string& directory,
                            QueryData& results) {
  for (const auto& hfile : kShellHistoryFiles) {
    boost::filesystem::path history_file = directory;
    history_file /= hfile;

    std::string history_content;
    if (!forensicReadFile(history_file, history_content).ok()) {
      // Cannot read a specific history file.
      continue;
    }

    for (const auto& line : split(history_content, "\n")) {
      Row r;
      r["uid"] = uid;
      r["command"] = line;
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
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      genShellHistoryForUser(row.at("uid"), row.at("directory"), results);
    }
  }

  return results;
}
}
}
