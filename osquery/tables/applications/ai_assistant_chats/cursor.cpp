/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/tables/applications/ai_assistant_chats/cursor.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kCursorApplication{"cursor"};

namespace {

/// Directory Cursor keeps its per-user state under.
const std::string kCursorDirectory{"Cursor"};
/// Cursor keeps one key/value row per message in this table.
const std::string kCursorBubbleQuery{
    "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:%'"};

} // namespace

void parseCursorBubble(const std::string& key,
                       const std::string& value,
                       const std::string& path,
                       std::vector<AIAssistantChat>& results) {
  // Keys look like "bubbleId:<conversation>:<message>". The message id is
  // always a UUID and so never holds a colon of its own, which makes the
  // last separator the end of the conversation id.
  const std::string prefix{"bubbleId:"};
  if (key.compare(0, prefix.size(), prefix) != 0) {
    return;
  }

  auto separator = key.rfind(':');
  if (separator == std::string::npos || separator <= prefix.size()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(value) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable Cursor message " << key << " in " << path;
    return;
  }

  const auto& bubble = doc.doc();

  // Cursor records who wrote a message as a number: 1 is the person at the
  // keyboard, 2 is the model.
  std::string role;
  auto type = bubble.FindMember("type");
  if (type != bubble.MemberEnd() && type->value.IsInt()) {
    if (type->value.GetInt() == 1) {
      role = kUserRole;
    } else if (type->value.GetInt() == 2) {
      role = kAssistantRole;
    }
  }

  if (role.empty()) {
    return;
  }

  auto text = stringMember(bubble, "text");
  if (text.empty()) {
    // Cursor writes a message for every step it takes, including the ones
    // that only ran a tool and said nothing.
    return;
  }

  AIAssistantChat chat;
  chat.application = kCursorApplication;
  chat.session_id = key.substr(prefix.size(), separator - prefix.size());
  chat.role = std::move(role);
  chat.message = std::move(text);
  chat.timestamp = timestampMember(bubble, "createdAt");
  chat.path = path;

  results.push_back(std::move(chat));
}
/// Reads the chat history Cursor keeps in its state databases.
void collectCursorChats(const fs::path& app_data_root,
                        std::vector<AIAssistantChat>& results) {
  auto cursor_user_dir = app_data_root / kCursorDirectory / "User";

  std::vector<std::string> databases;
  auto global_database = cursor_user_dir / "globalStorage" / "state.vscdb";
  if (pathExists(global_database).ok()) {
    databases.push_back(global_database.string());
  }

  // Recent builds keep every conversation in the global database, but
  // older ones wrote them per workspace instead.
  resolveFilePattern(cursor_user_dir / "workspaceStorage" / "%" / "state.vscdb",
                     databases,
                     GLOB_FILES);

  for (const auto& path : databases) {
    TableRows rows;
    auto status = genTableRowsForSqliteTable(path, kCursorBubbleQuery, rows);
    if (!status.ok()) {
      // A state database without a cursorDiskKV table is a workspace that
      // has never held a conversation, not a failure.
      VLOG(1) << "Could not read Cursor chat history from " << path << ": "
              << status.getMessage();
      continue;
    }

    for (const auto& table_row : rows) {
      auto row = static_cast<Row>(*table_row);

      auto key = row.find("key");
      auto value = row.find("value");
      if (key == row.end() || value == row.end()) {
        continue;
      }

      parseCursorBubble(key->second, value->second, path, results);
    }
  }
}

} // namespace tables
} // namespace osquery
