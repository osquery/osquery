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
#include <osquery/tables/applications/ai_assistant_chats/gemini.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kGeminiApplication{"gemini_cli"};

namespace {

/// Record types of a Gemini CLI session that this table reads.
const std::string kGeminiUserType{"user"};
const std::string kGeminiModelType{"gemini"};
/**
 * @brief Extracts readable text from a Gemini content value.
 *
 * @param content A string, text-part object, or array of these values.
 * @return std::string The concatenated text, or an empty string when no
 * readable text is present.
 */
std::string geminiContentText(const rapidjson::Value& content) {
  if (content.IsString()) {
    return content.GetString();
  }

  if (content.IsObject()) {
    return stringMember(content, "text");
  }

  if (!content.IsArray()) {
    return "";
  }

  std::string text;
  for (const auto& part : content.GetArray()) {
    if (part.IsString()) {
      text += part.GetString();
    } else {
      text += stringMember(part, "text");
    }
  }

  return text;
}
/**
 * @brief Determines whether user content represents a conversational prompt.
 *
 * @param content User-provided content to classify.
 * @return `true` if the trimmed content is conversational, `false` for empty
 *         content, question-mark commands, recognized slash commands, or
 *         injected session and hook context.
 */
bool isGeminiPrompt(const std::string& content) {
  auto trimmed = boost::algorithm::trim_copy(content);
  if (trimmed.empty() || trimmed.front() == '?') {
    return false;
  }

  if (trimmed.front() == '/') {
    // One word of a command's alphabet after the slash makes it a
    // command. Anything else opens with a path, and a prompt that starts
    // by naming a file is still a prompt.
    auto word = trimmed.find_first_of(" \t", 1);
    auto command = trimmed.substr(
        1, word == std::string::npos ? std::string::npos : word - 1);
    if (!command.empty() &&
        command.find_first_not_of("abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789_-") == std::string::npos) {
      return false;
    }
  }

  return trimmed.rfind("<session_context>", 0) != 0 &&
         trimmed.rfind("<hook_context>", 0) != 0;
}

/**
 * Reads one message record into `chat`, returning false for a record
 * that is not a message or that carries nothing anybody said.
 */
bool geminiMessage(const rapidjson::Value& record,
                   const std::string& path,
                   const std::string& session_id,
                   AIAssistantChat& chat) {
  std::string role;
  auto type = stringMember(record, "type");
  if (type == kGeminiUserType) {
    role = kUserRole;
  } else if (type == kGeminiModelType) {
    role = kAssistantRole;
  } else {
    // The remaining record types are notices the CLI showed the user
    // rather than anything either side of the conversation said.
    return false;
  }

  auto content = record.FindMember("content");
  if (content == record.MemberEnd()) {
    return false;
  }

  auto message = geminiContentText(content->value);
  if (message.empty() || (role == kUserRole && !isGeminiPrompt(message))) {
    return false;
  }

  chat.application = kGeminiApplication;
  chat.session_id = session_id;
  chat.role = std::move(role);
  chat.message = std::move(message);
  chat.timestamp = timestampMember(record, "timestamp");
  chat.path = path;

  return true;
}

/// Records a message under its id, replacing the one already there.
void rememberGeminiMessage(const std::string& id,
                           AIAssistantChat chat,
                           GeminiSession& session) {
  for (auto& remembered : session.messages) {
    if (remembered.first == id) {
      remembered.second = std::move(chat);
      return;
    }
  }

  session.messages.emplace_back(id, std::move(chat));
}

} // namespace

void parseGeminiSessionLine(const std::string& line,
                            const std::string& path,
                            GeminiSession& session) {
  auto record_text = boost::algorithm::trim_copy(line);
  if (record_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(record_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable record in Gemini session " << path;
    return;
  }

  const auto& record = doc.doc();

  // The opening record is the one that names the session and the project
  // it belongs to.
  auto named = stringMember(record, "sessionId");
  if (!named.empty() && !stringMember(record, "projectHash").empty()) {
    session.session_id = std::move(named);
    return;
  }

  // A record revising the session's metadata is not a message, except
  // when it carries the history itself. The CLI writes that when it
  // rewrites what a session holds, and reads it as a checkpoint that
  // replaces everything recorded before it, so this does the same. A
  // prompt can reach the file this way and no other.
  auto update = record.FindMember("$set");
  if (update != record.MemberEnd()) {
    if (!update->value.IsObject()) {
      return;
    }

    auto messages = update->value.FindMember("messages");
    if (messages == update->value.MemberEnd() || !messages->value.IsArray()) {
      return;
    }

    session.messages.clear();
    for (const auto& message : messages->value.GetArray()) {
      AIAssistantChat chat;
      if (message.IsObject() &&
          geminiMessage(message, path, session.session_id, chat)) {
        rememberGeminiMessage(
            stringMember(message, "id"), std::move(chat), session);
      }
    }

    return;
  }

  AIAssistantChat chat;
  if (geminiMessage(record, path, session.session_id, chat)) {
    rememberGeminiMessage(stringMember(record, "id"), std::move(chat), session);
  }
}

void parseGeminiSession(const std::string& content,
                        const std::string& path,
                        std::vector<AIAssistantChat>& results) {
  GeminiSession session;
  session.session_id = fs::path(path).stem().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseGeminiSessionLine(content.substr(start), path, session);
      break;
    }

    parseGeminiSessionLine(content.substr(start, end - start), path, session);
    start = end + 1;
  }

  finishGeminiSession(session, results);
}

void finishGeminiSession(GeminiSession& session,
                         std::vector<AIAssistantChat>& results) {
  for (auto& remembered : session.messages) {
    // The session names itself partway through its own file, so the
    // messages read before that point are named here instead.
    if (remembered.second.session_id.empty()) {
      remembered.second.session_id = session.session_id;
    }

    results.push_back(std::move(remembered.second));
  }

  session.messages.clear();
}

/**
 * Discovers and parses Gemini CLI session files for project and subagent chats.
 *
 * @param home Gemini home directory.
 * @param results Collection to which parsed chats are appended.
 */
void collectGeminiChats(const fs::path& home,
                        std::vector<AIAssistantChat>& results) {
  auto chats = home / ".gemini" / "tmp" / "%" / "chats";

  std::vector<std::string> sessions;
  resolveFilePattern(chats / "%.jsonl", sessions, GLOB_FILES);
  resolveFilePattern(chats / "%" / "%.jsonl", sessions, GLOB_FILES);

  for (const auto& path : sessions) {
    // The session names itself in its opening record; until that is read
    // the file name is the best answer available.
    GeminiSession session;
    session.session_id = fs::path(path).stem().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseGeminiSessionLine(line, path, session);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Gemini session " << path << ": "
              << status.getMessage();
      continue;
    }

    finishGeminiSession(session, results);
  }
}

} // namespace tables

} // namespace osquery
