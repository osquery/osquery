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

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/ai_assistant_chats/copilot_cli.h>
#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kCopilotCliApplication{"copilot_cli"};

namespace {

/**
 * @brief Names the kind of a Copilot CLI event.
 *
 * The CLI has written this under four different keys across releases, and
 * spells the values inconsistently, so the first one present is taken and
 * folded to lower case.
 */
std::string copilotEventKind(const rapidjson::Value& event) {
  for (const auto* key :
       {"hookEventName", "event", "eventType", "type", "role"}) {
    auto kind = stringMember(event, key);
    if (!kind.empty()) {
      return boost::algorithm::to_lower_copy(kind);
    }
  }

  return "";
}

/// Maps an event kind onto the role of the message it carries.
bool copilotEventRole(const std::string& kind, std::string& role) {
  if (kind == "userpromptsubmitted" || kind == "user_prompt_submitted" ||
      kind == "userprompt" || kind == "prompt" || kind == "user" ||
      kind == "human") {
    role = kUserRole;
    return true;
  }

  if (kind == "assistant" || kind == "assistantmessage" ||
      kind == "assistant_message" || kind == "agentmessage" ||
      kind == "agent_message" || kind == "ai" || kind == "model") {
    role = kAssistantRole;
    return true;
  }

  return false;
}

} // namespace

void parseCopilotCliEvent(const std::string& line,
                          const std::string& path,
                          const std::string& session_id,
                          std::vector<AIAssistantChat>& results) {
  auto event_text = boost::algorithm::trim_copy(line);
  if (event_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(event_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable event in Copilot CLI session " << path;
    return;
  }

  const auto& event = doc.doc();

  std::string role;
  if (!copilotEventRole(copilotEventKind(event), role)) {
    // The rest of the log is the session's tool use and its start and
    // stop, which carry no message.
    return;
  }

  // The body is a plain string under whichever of these the release used.
  std::string message;
  auto content = event.FindMember("content");
  if (content != event.MemberEnd()) {
    message = transcriptText(content->value);
  }

  for (const auto* key : {"text", "message", "prompt"}) {
    if (!message.empty()) {
      break;
    }
    message = stringMember(event, key);
  }

  if (message.empty()) {
    return;
  }

  AIAssistantChat chat;
  chat.application = kCopilotCliApplication;
  chat.role = std::move(role);
  chat.message = std::move(message);
  chat.path = path;

  chat.session_id = stringMember(event, "sessionId");
  if (chat.session_id.empty()) {
    chat.session_id = stringMember(event, "session_id");
  }
  if (chat.session_id.empty()) {
    chat.session_id = stringMember(event, "conversationId");
  }
  if (chat.session_id.empty()) {
    chat.session_id = session_id;
  }

  chat.timestamp = timestampMember(event, "timestamp");
  if (chat.timestamp == 0) {
    chat.timestamp = timestampMember(event, "createdAt");
  }
  if (chat.timestamp == 0) {
    chat.timestamp = timestampMember(event, "time");
  }

  results.push_back(std::move(chat));
}

void parseCopilotCliEvents(const std::string& content,
                           const std::string& path,
                           std::vector<AIAssistantChat>& results) {
  // Every session is a directory named after itself, holding the one log.
  auto session_id = fs::path(path).parent_path().filename().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseCopilotCliEvent(content.substr(start), path, session_id, results);
      break;
    }

    parseCopilotCliEvent(
        content.substr(start, end - start), path, session_id, results);
    start = end + 1;
  }
}

/**
 * @brief Collects the chat history the GitHub Copilot CLI keeps per session.
 *
 * This is a different store from the Copilot chat the VS Code extension
 * writes, which the vscode source reads instead.
 *
 * @param home User home directory containing the `.copilot/session-state`
 * hierarchy.
 * @param results Output collection to which parsed chats are appended.
 */
void collectCopilotCliChats(const fs::path& home,
                            std::vector<AIAssistantChat>& results) {
  std::vector<std::string> logs;
  resolveFilePattern(home / ".copilot" / "session-state" / "%" / "events.jsonl",
                     logs,
                     GLOB_FILES);

  for (const auto& path : logs) {
    // The events rarely name their session, but the directory holding the
    // log is named after it.
    auto session_id = fs::path(path).parent_path().filename().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseCopilotCliEvent(line, path, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Copilot CLI session " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
