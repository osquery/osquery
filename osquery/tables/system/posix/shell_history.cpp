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
  struct HistoryState hState;

  auto parseLine =
      [&hState, &uid, &history_file, &predicate](std::string& line) {
        std::smatch bash_timestamp_matches;
        std::smatch zsh_timestamp_matches;

        if (hState.prev_bash_timestamp.empty() &&
            std::regex_search(
                line, bash_timestamp_matches, hState.bash_timestamp_rx)) {
          hState.prev_bash_timestamp = bash_timestamp_matches[1];
          return;
        }

        auto r = make_table_row();

        if (!hState.prev_bash_timestamp.empty()) {
          r["time"] = INTEGER(hState.prev_bash_timestamp);
          r["command"] = std::move(line);
          hState.prev_bash_timestamp.clear();
        } else if (std::regex_search(
                       line, zsh_timestamp_matches, hState.zsh_timestamp_rx)) {
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

  auto parseChunk = [&hState, &parseLine](std::string& buffer, size_t size) {
    // We may be appending this chunk to the end of the previous.
    if (buffer.size() == size) {
      hState.content += std::move(buffer);
    } else {
      hState.content += buffer.substr(0, size);
    }

    // Search for newlines and parse each.
    size_t last_newline = 0;
    auto newline = hState.content.find('\n');
    while (newline != std::string::npos) {
      auto line = hState.content.substr(last_newline, newline - last_newline);
      parseLine(line);

      last_newline = newline + 1;
      newline = hState.content.find('\n', last_newline);
    }

    if (last_newline != hState.content.size() - 1) {
      // We need to buffer the end of the string.
      hState.content = hState.content.substr(last_newline);
    }
  };

  if (!readFile(history_file, 0, 4096, false, false, parseChunk, false)) {
    return;
  }

  // Parse the final line.
  if (!hState.content.empty()) {
    parseLine(hState.content);
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
