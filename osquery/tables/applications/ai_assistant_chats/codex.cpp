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
 * Reads the rollouts Codex writes, both from the CLI and from the desktop
 * and editor clients that drive it. They are filed by the date the
 * session started: sessions/<year>/<month>/<day>/rollout-<time>-<id>.jsonl
 */
void collectCodexChats(const fs::path& home,
                       std::vector<AIAssistantChat>& results) {
  std::vector<std::string> rollouts;
  resolveFilePattern(home / ".codex" / "sessions" / "%" / "%" / "%" / "%.jsonl",
                     rollouts,
                     GLOB_FILES);

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
