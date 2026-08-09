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

/// A saved conversation names the model's turns the way the API does.
const std::string kGeminiCheckpointModelRole{"model"};
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

void parseGeminiLogs(const std::string& content,
                     const std::string& path,
                     std::vector<AIAssistantChat>& results) {
  auto doc = JSON::newArray();
  if (!doc.fromString(content) || !doc.doc().IsArray()) {
    VLOG(1) << "Skipping unparsable Gemini log " << path;
    return;
  }

  // The log sits in the directory the CLI keeps a project's state under
  // and holds every prompt typed against that project, across all of the
  // sessions run there. Each entry names the session it belongs to; the
  // directory only has to answer for one that does not.
  auto project = fs::path(path).parent_path().filename().string();

  for (const auto& entry : doc.doc().GetArray()) {
    if (!entry.IsObject() || stringMember(entry, "type") != kGeminiUserType) {
      // A log holds prompts and nothing else, so a record typed as
      // anything else is not one this table can place.
      continue;
    }

    auto message = stringMember(entry, "message");
    if (message.empty() || !isGeminiPrompt(message)) {
      continue;
    }

    AIAssistantChat chat;
    chat.application = kGeminiApplication;
    chat.role = kUserRole;
    chat.message = std::move(message);
    chat.timestamp = timestampMember(entry, "timestamp");
    chat.path = path;

    // Naming the session the entry came from is what lets a prompt the
    // journal recorded too be recognised as the same one, rather than
    // read as a second prompt nobody typed.
    chat.session_id = stringMember(entry, "sessionId");
    if (chat.session_id.empty()) {
      chat.session_id = project;
    }

    results.push_back(std::move(chat));
  }
}

void parseGeminiCheckpoint(const std::string& content,
                           const std::string& path,
                           std::vector<AIAssistantChat>& results) {
  auto doc = JSON::newArray();
  if (!doc.fromString(content)) {
    VLOG(1) << "Skipping unparsable Gemini checkpoint " << path;
    return;
  }

  // Current releases wrap the turns in an object; older ones saved the
  // bare array.
  const rapidjson::Value* history = nullptr;
  if (doc.doc().IsArray()) {
    history = &doc.doc();
  } else if (doc.doc().IsObject()) {
    auto saved = doc.doc().FindMember("history");
    if (saved != doc.doc().MemberEnd() && saved->value.IsArray()) {
      history = &saved->value;
    }
  }

  if (history == nullptr) {
    return;
  }

  // A checkpoint is named by the tag the user saved it under, and the
  // default tag is the same one in every project. The directory it was
  // saved in is what tells two of them apart.
  auto file = fs::path(path);
  auto session_id = file.stem().string();
  auto project = file.parent_path().filename().string();
  if (!project.empty()) {
    session_id = project + "/" + session_id;
  }

  for (const auto& turn : history->GetArray()) {
    if (!turn.IsObject()) {
      continue;
    }

    // A checkpoint is the conversation as the model was given it, so a
    // turn names its role the way the API does rather than the way the
    // CLI types its own records: the model's turns are "model" here and
    // "gemini" in a session.
    std::string role;
    auto named = stringMember(turn, "role");
    if (named == kGeminiUserType) {
      role = kUserRole;
    } else if (named == kGeminiCheckpointModelRole) {
      role = kAssistantRole;
    } else {
      continue;
    }

    auto parts = turn.FindMember("parts");
    if (parts == turn.MemberEnd()) {
      continue;
    }

    auto message = geminiContentText(parts->value);
    if (message.empty() || (role == kUserRole && !isGeminiPrompt(message))) {
      // A turn that only called a tool carries no text of anyone's.
      continue;
    }

    AIAssistantChat chat;
    chat.application = kGeminiApplication;
    chat.session_id = session_id;
    chat.role = std::move(role);
    chat.message = std::move(message);
    chat.path = path;

    // A checkpoint records the conversation, not when it happened.
    chat.timestamp = 0;

    results.push_back(std::move(chat));
  }
}

/**
 * @brief Reads a whole file and hands it to a parser.
 *
 * @param path File to read.
 * @param kind Named for the log when the file cannot be read.
 * @param parse Parser to hand the content to.
 * @param results Collection the parser appends to.
 */
static void genGeminiFile(const std::string& path,
                          const char* kind,
                          void (*parse)(const std::string&,
                                        const std::string&,
                                        std::vector<AIAssistantChat>&),
                          std::vector<AIAssistantChat>& results) {
  std::string content;
  auto status = readFile(path, content);
  if (!status.ok()) {
    VLOG(1) << "Could not read Gemini " << kind << " " << path << ": "
            << status.getMessage();
    return;
  }

  parse(content, path, results);
}

/**
 * Discovers and parses Gemini CLI session files for project and subagent chats.
 *
 * @param home Gemini home directory.
 * @param results Collection to which parsed chats are appended.
 */
void collectGeminiChats(const fs::path& home,
                        std::vector<AIAssistantChat>& results) {
  auto project = home / ".gemini" / "tmp" / "%";
  auto chats = project / "chats";

  std::vector<std::string> sessions;
  resolveFilePattern(chats / "%.jsonl", sessions, GLOB_FILES);
  resolveFilePattern(chats / "%" / "%.jsonl", sessions, GLOB_FILES);

  // Before the CLI journalled its sessions it kept a flat log of the
  // prompts typed against a project, and it still writes one alongside.
  std::vector<std::string> logs;
  resolveFilePattern(project / "logs.json", logs, GLOB_FILES);
  for (const auto& path : logs) {
    genGeminiFile(path, "log", parseGeminiLogs, results);
  }

  // A conversation the user saved by hand is written whole rather than
  // journalled, and outlives the session it was saved from.
  std::vector<std::string> checkpoints;
  resolveFilePattern(project / "checkpoint-%.json", checkpoints, GLOB_FILES);
  resolveFilePattern(chats / "checkpoint-%.json", checkpoints, GLOB_FILES);
  for (const auto& path : checkpoints) {
    genGeminiFile(path, "checkpoint", parseGeminiCheckpoint, results);
  }

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
