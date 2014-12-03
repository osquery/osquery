// Copyright 2004-present Facebook. All Rights Reserved.

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

Status genShellHistoryForUser(const Row& row, QueryData& results) {
  std::string username;
  std::string directory;
  try {
    username = row.at("username");
    directory = row.at("directory");
  } catch (const std::out_of_range& e) {
    return Status(1, "Error retrieving query column");
  }

  std::vector<std::string> history_files;
  if (!osquery::listFilesInDirectory(directory, history_files).ok()) {
    return Status(1, "Cannot list files in: " + directory);
  }

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
  return Status(0, "OK");
}

QueryData genShellHistory(QueryContext& context) {
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
    auto status = genShellHistoryForUser(row, results);
  }

  return results;
}
}
}
