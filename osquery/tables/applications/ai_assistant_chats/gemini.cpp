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
 * @return std::string The concatenated text, or an empty string when no readable text is present.
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

} /**
 * @brief Parses a Gemini session record and appends conversational messages to the results.
 *
 * Updates the session identifier when the record contains session metadata. User and model
 * records with readable conversational content are converted to chat entries; other records
 * are skipped.
 *
 * @param line JSONL record to parse.
 * @param path Path of the session file containing the record.
 * @param session_id Session identifier to update from metadata records and associate with messages.
 * @param results Collection to which parsed chat entries are appended.
 */

void parseGeminiSessionLine(const std::string& line,
                            const std::string& path,
                            std::string& session_id,
                            std::vector<AIAssistantChat>& results) {
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
  // it belongs to. Records that revise the session's metadata afterwards
  // are not messages and are left alone.
  auto id = stringMember(record, "sessionId");
  if (!id.empty() && !stringMember(record, "projectHash").empty()) {
    session_id = std::move(id);
    return;
  }

  std::string role;
  auto type = stringMember(record, "type");
  if (type == kGeminiUserType) {
    role = kUserRole;
  } else if (type == kGeminiModelType) {
    role = kAssistantRole;
  } else {
    // The remaining record types are notices the CLI showed the user
    // rather than anything either side of the conversation said.
    return;
  }

  auto content = record.FindMember("content");
  if (content == record.MemberEnd()) {
    return;
  }

  auto message = geminiContentText(content->value);
  if (message.empty() || (role == kUserRole && !isGeminiPrompt(message))) {
    return;
  }

  AIAssistantChat chat;
  chat.application = kGeminiApplication;
  chat.session_id = session_id;
  chat.role = std::move(role);
  chat.message = std::move(message);
  chat.timestamp = timestampMember(record, "timestamp");
  chat.path = path;

  results.push_back(std::move(chat));
}
/**
 * @brief Parses a Gemini session's JSONL content into assistant chat records.
 *
 * @param content Session content containing one JSON record per line.
 * @param path Path of the session file.
 * @param results Vector to which parsed chat records are appended.
 */
void parseGeminiSession(const std::string& content,
                        const std::string& path,
                        std::vector<AIAssistantChat>& results) {
  auto session_id = fs::path(path).stem().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseGeminiSessionLine(content.substr(start), path, session_id, results);
      break;
    }

    parseGeminiSessionLine(
        content.substr(start, end - start), path, session_id, results);
    start = end + 1;
  }
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
    auto session_id = fs::path(path).stem().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseGeminiSessionLine(line, path, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Gemini session " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
