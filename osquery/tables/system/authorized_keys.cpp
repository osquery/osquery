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


#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/sql.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHAuthorizedkeys = {
    ".ssh/authorized_keys",
};

void genSSHkeysForUser(const std::string& username,
                            const std::string& directory,
                            QueryData& results) {
  for (const auto& kfile : kSSHAuthorizedkeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;

    std::string keys_content;
    if (!readFile(keys_file, keys_content).ok()) {
      // Cannot read a specific keys file.
      continue;
    }

    for (const auto& line : split(keys_content, "\n")) {
      Row r;
      r["username"] = username;
      r["key"] = line;
      r["key_file"] = keys_file.string();
      results.push_back(r);
    }
  }
}

QueryData getAuthorizedKeys(QueryContext& context) {
  QueryData results;

  // Select only the home directory for this user.
  QueryData users;
  if (!context.constraints["username"].exists(EQUALS)) {
    users =
        SQL::selectAllFrom("users", "uid", EQUALS, std::to_string(getuid()));
  } else {
    auto usernames = context.constraints["username"].getAll(EQUALS);
    for (const auto& username : usernames) {
      // Use a predicated select all for each user.
      auto user = SQL::selectAllFrom("users", "username", EQUALS, username);
      users.insert(users.end(), user.begin(), user.end());
    }
  }

  // Iterate over each user
  for (const auto& row : users) {
    if (row.count("username") > 0 && row.count("directory") > 0) {
       genSSHkeysForUser(row.at("username"), row.at("directory"), results);
    }
  }

  return results;
}
}
}
