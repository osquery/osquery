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
#include <osquery/tables/applications/ai_assistant_chats/kimi.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kKimiApplication{"kimi_code"};

namespace {

/// Record types of a Kimi Code wire journal that this table reads.
const std::string kKimiPromptRecord{"turn.prompt"};
const std::string kKimiLoopEventRecord{"context.append_loop_event"};

/// The loop event that carries a piece of what the model said.
const std::string kKimiContentPart{"content.part"};

/// Reads the text out of Kimi's content parts, ignoring its reasoning.
std::string kimiPartText(const rapidjson::Value& part) {
  if (!part.IsObject() || stringMember(part, "type") != "text") {
    return "";
  }

  return stringMember(part, "text");
}

} // namespace

std::string kimiSessionId(const std::string& path) {
  // A journal lives at sessions/<date>/<session>/agents/<agent>/wire.jsonl,
  // and nothing inside it names the session, so the path is the only
  // place to read it from.
  std::vector<std::string> parts;
  for (const auto& part : fs::path(path)) {
    parts.push_back(part.string());
  }

  for (std::size_t i = 0; i + 5 < parts.size(); ++i) {
    if (parts[i] == "sessions" && parts[i + 3] == "agents" &&
        parts[i + 5] == "wire.jsonl") {
      return parts[i + 2];
    }
  }

  return "";
}

void parseKimiWireLine(const std::string& line,
                       const std::string& path,
                       const std::string& session_id,
                       std::vector<AIAssistantChat>& results) {
  auto record_text = boost::algorithm::trim_copy(line);
  if (record_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(record_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable record in Kimi Code journal " << path;
    return;
  }

  const auto& record = doc.doc();

  AIAssistantChat chat;
  chat.application = kKimiApplication;
  chat.session_id = session_id;
  chat.path = path;
  chat.timestamp = timestampMember(record, "time");
  if (chat.timestamp == 0) {
    chat.timestamp = timestampMember(record, "created_at");
  }

  auto type = stringMember(record, "type");
  if (type == kKimiPromptRecord) {
    // Kimi records the same prompt twice, here and again as a replayed
    // message. Only this one says who it came from, so it is the one to
    // read and the replay is left alone.
    auto origin = record.FindMember("origin");
    if (origin == record.MemberEnd() || !origin->value.IsObject() ||
        stringMember(origin->value, "kind") != kUserRole) {
      return;
    }

    auto input = record.FindMember("input");
    if (input == record.MemberEnd() || !input->value.IsArray()) {
      return;
    }

    for (const auto& part : input->value.GetArray()) {
      auto text = kimiPartText(part);
      if (text.empty()) {
        continue;
      }

      auto message = chat;
      message.role = kUserRole;
      message.message = std::move(text);
      results.push_back(std::move(message));
    }

    return;
  }

  if (type != kKimiLoopEventRecord) {
    // The rest of the wire is state, permission and usage bookkeeping.
    return;
  }

  auto event = record.FindMember("event");
  if (event == record.MemberEnd() || !event->value.IsObject() ||
      stringMember(event->value, "type") != kKimiContentPart) {
    return;
  }

  auto part = event->value.FindMember("part");
  if (part == event->value.MemberEnd()) {
    return;
  }

  auto text = kimiPartText(part->value);
  if (text.empty()) {
    return;
  }

  chat.role = kAssistantRole;
  chat.message = std::move(text);

  results.push_back(std::move(chat));
}

void parseKimiWire(const std::string& content,
                   const std::string& path,
                   std::vector<AIAssistantChat>& results) {
  auto session_id = kimiSessionId(path);

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseKimiWireLine(content.substr(start), path, session_id, results);
      break;
    }

    parseKimiWireLine(
        content.substr(start, end - start), path, session_id, results);
    start = end + 1;
  }
}

/**
 * @brief Collects the wire journals Kimi Code writes per session.
 *
 * @param home User home directory containing the `.kimi-code/sessions`
 * hierarchy.
 * @param results Output collection to which parsed chats are appended.
 */
void collectKimiChats(const fs::path& home,
                      std::vector<AIAssistantChat>& results) {
  std::vector<std::string> journals;

  // Every agent a session ran gets a journal of its own, the main one and
  // the subagents it delegated to alike.
  resolveFilePattern(home / ".kimi-code" / "sessions" / "%" / "%" / "agents" /
                         "%" / "wire.jsonl",
                     journals,
                     GLOB_FILES);

  for (const auto& path : journals) {
    auto session_id = kimiSessionId(path);
    if (session_id.empty()) {
      // A layout this does not recognise still names the agent that wrote
      // the journal, which is better than reporting no session at all.
      session_id = fs::path(path).parent_path().filename().string();
    }

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseKimiWireLine(line, path, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Kimi Code journal " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
