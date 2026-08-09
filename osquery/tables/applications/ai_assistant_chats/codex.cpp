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

#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/ai_assistant_chats/codex.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kCodexApplication{"codex"};

namespace {

/// Entry types of a Codex rollout that this table reads.
const std::string kCodexSessionMetaType{"session_meta"};
const std::string kCodexEventType{"event_msg"};

} // namespace

/**
 * @brief Parses a Codex rollout entry and records supported chat messages.
 *
 * Malformed, unsupported, and empty entries are ignored. Session metadata
 * updates the current session identifier.
 *
 * @param line Rollout entry encoded as a JSON line.
 * @param path Path to the rollout file associated with the entry.
 * @param session_id Current session identifier, updated by session metadata
 * entries.
 * @param results Collection to which parsed chat messages are appended.
 */

void parseCodexRolloutLine(const std::string& line,
                           const std::string& path,
                           std::string& session_id,
                           std::vector<AIAssistantChat>& results) {
  auto entry_text = boost::algorithm::trim_copy(line);
  if (entry_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(entry_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable entry in Codex rollout " << path;
    return;
  }

  const auto& entry = doc.doc();

  auto payload = entry.FindMember("payload");
  if (payload == entry.MemberEnd() || !payload->value.IsObject()) {
    return;
  }

  auto type = stringMember(entry, "type");
  if (type == kCodexSessionMetaType) {
    auto id = stringMember(payload->value, "session_id");
    if (!id.empty()) {
      session_id = id;
    }
    return;
  }

  if (type != kCodexEventType) {
    // The other entries are the raw conversation held with the model,
    // which mixes in the instructions and context Codex supplies on the
    // user's behalf. The events below are what the person saw.
    return;
  }

  std::string role;
  auto event = stringMember(payload->value, "type");
  if (event == "user_message") {
    role = kUserRole;
  } else if (event == "agent_message") {
    role = kAssistantRole;
  } else {
    return;
  }

  auto message = stringMember(payload->value, "message");
  if (message.empty()) {
    return;
  }

  AIAssistantChat chat;
  chat.application = kCodexApplication;
  chat.session_id = session_id;
  chat.role = std::move(role);
  chat.message = std::move(message);
  chat.timestamp = timestampMember(entry, "timestamp");
  chat.path = path;

  results.push_back(std::move(chat));
}
/**
 * @brief Parses a Codex rollout and appends its chat messages to the results.
 *
 * @param content Rollout content in JSONL format.
 * @param path Path to the rollout file.
 * @param results Collection to which parsed chat messages are appended.
 */
void parseCodexRollout(const std::string& content,
                       const std::string& path,
                       std::vector<AIAssistantChat>& results) {
  auto session_id = fs::path(path).stem().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseCodexRolloutLine(content.substr(start), path, session_id, results);
      break;
    }

    parseCodexRolloutLine(
        content.substr(start, end - start), path, session_id, results);
    start = end + 1;
  }
}
/**
 * @brief Collects Codex chat messages from rollout files in the user's home
 * directory.
 *
 * @param home User home directory containing the `.codex/sessions` hierarchy.
 * @param results Output collection to which parsed chats are appended.
 */
void collectCodexChats(const fs::path& home,
                       std::vector<AIAssistantChat>& results) {
  std::vector<std::string> rollouts;

  // Codex files a rollout under the date it was started, and moves the
  // ones it has retired into an archive of the same shape. A session the
  // user has since cleared out of the CLI is still on disk there.
  for (const auto* directory : {"sessions", "archived_sessions"}) {
    resolveFilePattern(
        home / ".codex" / directory / "%" / "%" / "%" / "%.jsonl",
        rollouts,
        GLOB_FILES);
  }

  for (const auto& path : rollouts) {
    // The session id arrives in the rollout's opening entry; until then
    // the file name is the best answer available.
    auto session_id = fs::path(path).stem().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseCodexRolloutLine(line, path, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Codex rollout " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
