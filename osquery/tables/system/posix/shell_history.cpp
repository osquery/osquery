/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>
#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/posix/shell_history.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/system/system.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kShellHistoryFiles = {
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".history",
    ".sh_history",
    ".ash_history",
};

struct HistoryState {
  std::string content;
  std::regex bash_timestamp_rx{"^#([0-9]+)$"};
  std::regex zsh_timestamp_rx{"^: {0,10}([0-9]{1,11}):[0-9]+;(.*)$"};
  std::string prev_bash_timestamp;
};

void genShellHistoryFromFile(
    const std::string& uid,
    const boost::filesystem::path& history_file,
    std::function<void(DynamicTableRowHolder& row)> predicate) {
  struct HistoryState history_state;

  auto parseLine = [&history_state, &uid, &history_file, &predicate](
                       std::string& line) {
    std::smatch bash_timestamp_matches;
    std::smatch zsh_timestamp_matches;

    if (history_state.prev_bash_timestamp.empty() &&
        std::regex_search(
            line, bash_timestamp_matches, history_state.bash_timestamp_rx)) {
      history_state.prev_bash_timestamp = bash_timestamp_matches[1];
      return;
    }

    auto r = make_table_row();

    if (!history_state.prev_bash_timestamp.empty()) {
      r["time"] = INTEGER(history_state.prev_bash_timestamp);
      r["command"] = std::move(line);
      history_state.prev_bash_timestamp.clear();
    } else if (std::regex_search(line,
                                 zsh_timestamp_matches,
                                 history_state.zsh_timestamp_rx)) {
      std::string timestamp = zsh_timestamp_matches[1];
      r["time"] = INTEGER(timestamp);
      r["command"] = zsh_timestamp_matches[2];
    } else {
      r["time"] = INTEGER(0);
      r["command"] = std::move(line);
    }

    r["uid"] = uid;
    r["history_file"] = history_file.string();
    predicate(r);
  };

  auto parseChunk = [&history_state, &parseLine](std::string_view buffer) {
    history_state.content += buffer;

    // Search for newlines and parse each.
    size_t last_newline = 0;
    auto newline = history_state.content.find('\n');
    while (newline != std::string::npos) {
      auto line =
          history_state.content.substr(last_newline, newline - last_newline);
      parseLine(line);

      last_newline = newline + 1;
      newline = history_state.content.find('\n', last_newline);
    }

    if (last_newline != history_state.content.size() - 1) {
      // We need to buffer the end of the string.
      history_state.content = history_state.content.substr(last_newline);
    }
  };

  if (!readFile(history_file, parseChunk)) {
    return;
  }

  // Parse the final line.
  if (!history_state.content.empty()) {
    parseLine(history_state.content);
  }
}

void genShellHistoryForUser(
    const std::string& uid,
    const std::string& gid,
    const std::string& directory,
    std::function<void(DynamicTableRowHolder& row)> predicate) {
  for (const auto& hfile : kShellHistoryFiles) {
    boost::filesystem::path history_file = directory;
    history_file /= hfile;
    genShellHistoryFromFile(uid, history_file, predicate);
  }
}

void genShellHistoryFromBashSessions(
    const std::string& uid,
    const std::string& directory,
    std::function<void(DynamicTableRowHolder& row)> predicate) {
  boost::filesystem::path bash_sessions = directory;
  bash_sessions /= ".bash_sessions";

  if (pathExists(bash_sessions)) {
    bash_sessions /= "*.history";
    std::vector<std::string> session_hist_files;
    resolveFilePattern(bash_sessions, session_hist_files);

    for (const auto& hfile : session_hist_files) {
      boost::filesystem::path history_file = hfile;
      genShellHistoryFromFile(uid, history_file, predicate);
    }
  }
}

void genShellHistory(RowYield& yield, QueryContext& context) {
  auto predicate = [&yield](DynamicTableRowHolder& r) { yield(std::move(r)); };

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto dir = row.find("directory");
    if (uid != row.end() && gid != row.end() && dir != row.end()) {
      genShellHistoryForUser(uid->second, gid->second, dir->second, predicate);
      genShellHistoryFromBashSessions(uid->second, dir->second, predicate);
    }
  }
}
} // namespace tables
} // namespace osquery
