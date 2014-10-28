// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <vector>

#include <pwd.h>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"
#include "osquery/sql.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history", ".zsh_history", ".zhistory", ".history",
};

QueryData genBashHistory() {
  QueryData results;
  std::string sql_str;

  if (!getuid()) {
    sql_str = "SELECT username,directory FROM users";
  } else {
    struct passwd* pwd = nullptr;
    pwd = getpwuid(getuid());
    // TODO: https://github.com/facebook/osquery/issues/244
    sql_str = "SELECT username,directory FROM users WHERE username = '" +
              std::string(pwd->pw_name) + "';";
  }

  auto sql = SQL(sql_str);

  if (!sql.ok()) {
    LOG(ERROR) << "Error executing SQL: " << sql.getMessageString();
    return results;
  }

  for (const auto& row : sql.rows()) {
    std::string username;
    std::string directory;
    try {
      username = row.at("username");
      directory = row.at("directory");
    } catch (const std::out_of_range& e) {
      LOG(ERROR) << "Error retrieving query column";
      continue;
    }

    std::vector<std::string> history_files;
    Status d = listFilesInDirectory(directory, history_files);
    if (!d.ok()) {
      LOG(ERROR) << "Error listing history files in " << directory << ": "
                 << d.toString();
      continue;
    }

    for (const auto& hfile : kShellHistoryFiles) {
      std::string history_content;
      std::string::iterator last_c = directory.end() - 1;
      if (*last_c != '/') {
        directory += '/';
      }
      std::string user_history = directory + hfile;
      Status s = readFile(user_history, history_content);
      if (s.ok()) {
        for (const auto& line : split(history_content, "\n")) {
          Row r;
          r["username"] = std::string(username);
          r["command"] = std::string(line);
          r["history_file"] = std::string(user_history);
          results.push_back(r);
        }
      }
    }
  }

  return results;
}
}
}
