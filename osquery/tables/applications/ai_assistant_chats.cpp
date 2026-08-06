/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <exception>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/ai_assistant_chats/antigravity.h>
#include <osquery/tables/applications/ai_assistant_chats/claude.h>
#include <osquery/tables/applications/ai_assistant_chats/codex.h>
#include <osquery/tables/applications/ai_assistant_chats/cursor.h>
#include <osquery/tables/applications/ai_assistant_chats/gemini.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/tables/applications/ai_assistant_chats/vscode.h>
#include <osquery/tables/system/system_utils.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

namespace {

/// The directories one user's chat history can be found under.
struct UserPaths final {
  fs::path home;
  fs::path app_data_root;
};

/**
 * A source of chat history. Which directories it reads and what format it
 * finds there are its own business; all it has in common with the others
 * is the rows it produces, so a plain function is all the interface a
 * source needs.
 */
using ChatSource = void (*)(const UserPaths&, std::vector<AIAssistantChat>&);

struct ChatSourceEntry final {
  /// Named for the log when this source fails.
  const char* name;

  /// The applications it can report, so that a query asking for one of
  /// them does not pay to read the stores of every other.
  std::vector<std::string> applications;

  ChatSource collect;
};

/**
 * @brief Provides the configured chat-history sources supported by the table.
 *
 * @return const std::vector<ChatSourceEntry>& The configured chat sources.
 */
const std::vector<ChatSourceEntry>& chatSources() {
  static const std::vector<ChatSourceEntry> sources{
      {"claude",
       {kClaudeCodeApplication, kClaudeDesktopApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectClaudeChats(paths.home, paths.app_data_root, results);
       }},
      {"codex",
       {kCodexApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectCodexChats(paths.home, results);
       }},
      {"gemini",
       {kGeminiApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectGeminiChats(paths.home, results);
       }},
      {"cursor",
       {kCursorApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectCursorChats(paths.app_data_root, results);
       }},
      {"antigravity",
       {kAntigravityApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectAntigravityChats(paths.home, results);
       }},
      {"vscode",
       {kCopilotApplication},
       [](const UserPaths& paths, std::vector<AIAssistantChat>& results) {
         collectVSCodeChats(paths.app_data_root, results);
       }},
  };

  return sources;
}

/**
 * @brief Determines whether a chat source matches the requested applications.
 *
 * @param source Chat source and its supported applications.
 * @param applications Applications requested by the query.
 * @return true if no applications were requested or the source supports a requested application, false otherwise.
 */
bool sourceIsWanted(const ChatSourceEntry& source,
                    const std::set<std::string>& applications) {
  if (applications.empty()) {
    return true;
  }

  for (const auto& application : source.applications) {
    if (applications.count(application) > 0) {
      return true;
    }
  }

  return false;
}

/// The users to read, one entry per uid and home directory.
std::set<std::pair<std::string, std::string>> usersToRead(
    const QueryContext& context) {
  std::set<std::pair<std::string, std::string>> users;

  for (const auto& row : usersFromContext(context)) {
    auto uid = row.find("uid");
    auto directory = row.find("directory");
    if (uid == row.end() || directory == row.end() ||
        directory->second.empty()) {
      continue;
    }

    users.insert({uid->second, directory->second});
  }

  return users;
}

} /**
 * @brief Collects AI assistant chat history for eligible users and applications.
 *
 * @param context Query constraints used to select users and applications.
 * @return QueryData Rows containing chat messages and their associated metadata.
 */

QueryData genAIAssistantChats(QueryContext& context) {
  QueryData results;

  // A query after one application should not pay to read the stores of
  // all the others.
  auto applications = context.constraints["application"].getAll(EQUALS);

  for (const auto& user : usersToRead(context)) {
    const auto& uid = user.first;
    UserPaths paths{fs::path(user.second), {}};
    paths.app_data_root = appDataRoot(paths.home);

    for (const auto& source : chatSources()) {
      if (!sourceIsWanted(source, applications)) {
        continue;
      }

      std::vector<AIAssistantChat> chats;

      // Every source already skips what it cannot read, but these are
      // undocumented formats on someone else's disk: one that manages to
      // throw anyway should cost its own rows, not the whole table.
      try {
        source.collect(paths, chats);
      } catch (const std::exception& error) {
        LOG(WARNING) << "Skipping " << source.name << " chat history for uid "
                     << uid << ": " << error.what();
      }

      // Converted a source at a time, so that a machine with a large
      // history holds one source's messages rather than all of them on
      // top of the rows they became.
      for (auto& chat : chats) {
        Row r;
        r["uid"] = uid;
        r["application"] = std::move(chat.application);
        r["session_id"] = std::move(chat.session_id);
        r["role"] = std::move(chat.role);
        r["message"] = std::move(chat.message);
        r["timestamp"] = BIGINT(chat.timestamp);
        r["path"] = std::move(chat.path);

        results.push_back(std::move(r));
      }
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
