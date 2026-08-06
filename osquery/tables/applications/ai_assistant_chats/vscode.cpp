/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <utility>
#include <vector>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/ai_assistant_chats/vscode.h>
#include <osquery/utils/json/json.h>

#include <rapidjson/pointer.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kCopilotApplication{"copilot"};

namespace {

/**
 * Editors built on VS Code, and the application each of their per-user
 * directories belongs to. They all inherit the same chat session store,
 * so one parser covers the lot.
 */
const std::vector<std::pair<std::string, std::string>> kVSCodeDirectories{
    {"Code", kCopilotApplication},
    {"Code - Insiders", kCopilotApplication},
};

/**
 * The records of a chat session journal: the session as it stood when the
 * file was opened, then every change made to it since.
 */
const int kSessionSnapshotRecord{0};
const int kSessionSetRecord{1};
const int kSessionAppendRecord{2};

/// The response part that is the model working rather than answering.
const std::string kThinkingPart{"thinking"};

/**
 * @brief Converts a journal path into a JSON Pointer.
 *
 * Supports a single string or 64-bit integer token, or an array of such
 * tokens. String tokens use JSON Pointer escaping for `~` and `/`.
 *
 * @param path Journal path token or array of tokens.
 * @param pointer Receives the resulting JSON Pointer.
 * @return `true` if the path contains supported, nonempty tokens; `false`
 * otherwise.
 */
bool journalPointer(const rapidjson::Value& path, std::string& pointer) {
  auto append = [&pointer](const rapidjson::Value& token) {
    if (token.IsString()) {
      pointer += '/';
      for (const auto character : std::string(token.GetString())) {
        // The two characters a pointer spells out rather than carries.
        if (character == '~') {
          pointer += "~0";
        } else if (character == '/') {
          pointer += "~1";
        } else {
          pointer += character;
        }
      }
      return true;
    }

    if (token.IsInt64()) {
      pointer += '/' + std::to_string(token.GetInt64());
      return true;
    }

    return false;
  };

  pointer.clear();
  if (!path.IsArray()) {
    return append(path);
  }

  for (const auto& token : path.GetArray()) {
    if (!append(token)) {
      return false;
    }
  }

  return !pointer.empty();
}

/**
 * Reconstructs a chat session from newline-delimited journal records.
 *
 * @param content Journal content containing snapshot, set, and append records.
 * @param session Output session document populated from the journal.
 * @return true if the journal contains a valid snapshot record, false otherwise.
 */
bool replayChatSessionJournal(const std::string& content, JSON& session) {
  auto& document = session.doc();
  auto& allocator = document.GetAllocator();
  bool opened = false;

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    auto line = content.substr(
        start, end == std::string::npos ? std::string::npos : end - start);
    start = end == std::string::npos ? content.size() + 1 : end + 1;

    if (line.empty()) {
      continue;
    }

    auto record = JSON::newObject();
    if (!record.fromString(line) || !record.doc().IsObject()) {
      continue;
    }

    auto kind = record.doc().FindMember("kind");
    auto value = record.doc().FindMember("v");
    if (kind == record.doc().MemberEnd() || !kind->value.IsInt() ||
        value == record.doc().MemberEnd()) {
      continue;
    }

    if (kind->value.GetInt() == kSessionSnapshotRecord) {
      if (!value->value.IsObject()) {
        continue;
      }

      document.CopyFrom(value->value, allocator);
      opened = true;
      continue;
    }

    auto path = record.doc().FindMember("k");
    std::string pointer;
    if (!opened || path == record.doc().MemberEnd() ||
        !journalPointer(path->value, pointer)) {
      continue;
    }

    rapidjson::Pointer target(pointer.c_str());
    if (!target.IsValid()) {
      continue;
    }

    if (kind->value.GetInt() == kSessionSetRecord) {
      rapidjson::Value copy(value->value, allocator);
      target.Set(document, copy);
      continue;
    }

    if (kind->value.GetInt() != kSessionAppendRecord ||
        !value->value.IsArray()) {
      continue;
    }

    auto* array = target.Get(document);
    if (array == nullptr || !array->IsArray()) {
      array = &target.Create(document);
      array->SetArray();
    }

    for (const auto& element : value->value.GetArray()) {
      rapidjson::Value copy(element, allocator);
      array->PushBack(copy, allocator);
    }
  }

  return opened;
}

/**
 * @brief Extracts the prompt text from a chat request.
 *
 * @param request Chat request containing a direct message or nested text value.
 * @return std::string The request prompt, or an empty string when unavailable.
 */
std::string chatRequestPrompt(const rapidjson::Value& request) {
  auto message = request.FindMember("message");
  if (message == request.MemberEnd()) {
    return "";
  }

  if (message->value.IsString()) {
    return message->value.GetString();
  }

  return stringMember(message->value, "text");
}
/**
 * Reconstructs the assistant's response from its streamed parts.
 *
 * @param request Chat request containing the response data.
 * @return Concatenated response text, excluding model thinking parts.
 */
std::string chatRequestResponse(const rapidjson::Value& request) {
  auto response = request.FindMember("response");
  if (response == request.MemberEnd()) {
    return "";
  }

  if (response->value.IsString()) {
    return response->value.GetString();
  }

  if (!response->value.IsArray()) {
    return "";
  }

  std::string text;
  for (const auto& part : response->value.GetArray()) {
    if (part.IsString()) {
      text += part.GetString();
      continue;
    }

    if (stringMember(part, "kind") == kThinkingPart) {
      // The model reasoning rather than answering, which the editor
      // shows apart from the reply.
      continue;
    }

    auto value = stringMember(part, "value");
    if (value.empty()) {
      // Some kinds of part carry their text one level down instead.
      auto content = part.FindMember("content");
      if (content != part.MemberEnd()) {
        value = stringMember(content->value, "value");
      }
    }

    text += value;
  }

  return text;
}

} /**
 * @brief Extracts user prompts and assistant responses from a VS Code chat-session file.
 *
 * @param content Serialized chat-session content, either as a JSON object or journal records.
 * @param path Path to the chat-session file.
 * @param application Application identifier associated with the session.
 * @param results Collection to which extracted chat rows are appended.
 */

void parseChatSessionFile(const std::string& content,
                          const std::string& path,
                          const std::string& application,
                          std::vector<AIAssistantChat>& results) {
  auto doc = JSON::newObject();
  if (!doc.fromString(content) || !doc.doc().IsObject()) {
    // Newer editors journal a session rather than rewriting it whole, so
    // a file that is not one object is one object per line instead.
    doc = JSON::newObject();
    if (!replayChatSessionJournal(content, doc)) {
      VLOG(1) << "Could not parse chat session " << path;
      return;
    }
  }

  const auto& session = doc.doc();

  auto session_id = stringMember(session, "sessionId");
  if (session_id.empty()) {
    session_id = fs::path(path).stem().string();
  }

  auto requests = session.FindMember("requests");
  if (requests == session.MemberEnd() || !requests->value.IsArray()) {
    return;
  }

  for (const auto& request : requests->value.GetArray()) {
    if (!request.IsObject()) {
      continue;
    }

    // A request holds both what was asked and what came back, so it can
    // produce a row for each.
    auto timestamp = timestampMember(request, "timestamp");

    auto prompt = chatRequestPrompt(request);
    if (!prompt.empty()) {
      AIAssistantChat chat;
      chat.application = application;
      chat.session_id = session_id;
      chat.role = kUserRole;
      chat.message = std::move(prompt);
      chat.timestamp = timestamp;
      chat.path = path;
      results.push_back(std::move(chat));
    }

    auto response = chatRequestResponse(request);
    if (!response.empty()) {
      AIAssistantChat chat;
      chat.application = application;
      chat.session_id = session_id;
      chat.role = kAssistantRole;
      chat.message = std::move(response);
      chat.timestamp = timestamp;
      chat.path = path;
      results.push_back(std::move(chat));
    }
  }
}
/**
 * @brief Collects chat sessions stored by VS Code and VS Code Insiders.
 *
 * @param app_data_root Root directory containing the editor application data.
 * @param results Vector to which parsed chat rows are appended.
 */
void collectVSCodeChats(const fs::path& app_data_root,
                        std::vector<AIAssistantChat>& results) {
  for (const auto& directory : kVSCodeDirectories) {
    auto user_dir = app_data_root / directory.first / "User";

    // A session was one JSON file before these editors moved to
    // journaling one, which came with an extension of its own.
    std::vector<std::string> sessions;
    for (const auto& extension : {"%.json", "%.jsonl"}) {
      resolveFilePattern(
          user_dir / "workspaceStorage" / "%" / "chatSessions" / extension,
          sessions,
          GLOB_FILES);

      // Chats started in a window with no folder open are not tied to a
      // workspace and live next to the global state instead.
      resolveFilePattern(
          user_dir / "globalStorage" / "emptyWindowChatSessions" / extension,
          sessions,
          GLOB_FILES);
    }

    for (const auto& path : sessions) {
      std::string content;
      auto status = readFile(path, content);
      if (!status.ok()) {
        VLOG(1) << "Could not read chat session " << path << ": "
                << status.getMessage();
        continue;
      }

      parseChatSessionFile(content, path, directory.second, results);
    }
  }
}

} // namespace tables
} // namespace osquery
