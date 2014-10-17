// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <glog/logging.h>

#include <pwd.h>

#include <boost/lexical_cast.hpp>

#include "osquery/sql.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData genBashHistory() {
  QueryData results;
  std::string history_content;
  std::string history_file = ".bash_history";
  std::string user_history;
  std::string sql_str;

  if (!getuid()) {
    sql_str = "SELECT username,directory FROM users";
  } else {
    struct passwd *pwd = nullptr;
    pwd = getpwuid(getuid());
    // TODO: Come back here when osquery supports parametrized queries, until then SQLi!
    sql_str = "SELECT username,directory FROM users WHERE username = '" + std::string(pwd->pw_name) + "';";
  }

  auto sql = SQL(sql_str);

  if (sql.ok()) {
    for (const auto& row : sql.rows()) {
      try {
        auto username = row.at("username");
        auto directory = row.at("directory");
        std::string::iterator last_c = directory.end() - 1;
        if (*last_c == '/') {
          user_history = directory + history_file;
        } else {
          user_history = directory + '/' + history_file;
        }
        Status s = readFile(user_history, history_content);
        if (s.ok()) {
          for (const auto& line : split(history_content, "\n")) {
            Row r;
            r["username"] = std::string(username);
            r["command"] = std::string(line);
            results.push_back(r);
          }
        }
      } catch (const std::out_of_range& e) {
        LOG(ERROR) << "Error retrieving query column";
      }
    }
  } else {
    LOG(ERROR) << sql.getMessageString();
  }

  return results;
}
}
}
