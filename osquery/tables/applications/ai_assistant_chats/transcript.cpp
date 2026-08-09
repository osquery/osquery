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

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

std::string transcriptText(const rapidjson::Value& content) {
  if (content.IsString()) {
    return content.GetString();
  }

  if (content.IsObject()) {
    return stringMember(content, "text");
  }

  if (!content.IsArray()) {
    return "";
  }

  std::vector<std::string> chunks;
  for (const auto& block : content.GetArray()) {
    if (block.IsString()) {
      chunks.push_back(block.GetString());
      continue;
    }

    // A block names its own kind, and only the text ones are the message:
    // the rest are the tool calls and their output, which this table does
    // not report. A block that names no kind at all but carries text is
    // still text.
    auto type = stringMember(block, "type");
    if (!type.empty() && type != "text") {
      continue;
    }

    auto text = stringMember(block, "text");
    if (!text.empty()) {
      chunks.push_back(std::move(text));
    }
  }

  return boost::algorithm::join(chunks, "\n\n");
}

bool transcriptRole(const std::string& name, std::string& role) {
  if (name == kUserRole || name == "human") {
    role = kUserRole;
    return true;
  }

  if (name == kAssistantRole || name == "ai" || name == "model") {
    role = kAssistantRole;
    return true;
  }

  return false;
}

void parseTranscriptLine(const std::string& line,
                         const std::string& path,
                         const std::string& application,
                         const std::string& session_id,
                         std::vector<AIAssistantChat>& results) {
  auto record_text = boost::algorithm::trim_copy(line);
  if (record_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(record_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable record in transcript " << path;
    return;
  }

  const auto& record = doc.doc();

  // These stores have named the record's kind both ways across releases.
  // A record carrying both is one that types itself and then repeats the
  // role inside its message, so the type is the one to believe.
  std::string role;
  auto kind = stringMember(record, "type");
  if (kind.empty()) {
    kind = stringMember(record, "role");
  }

  if (!transcriptRole(kind, role)) {
    // The remaining records are the tool calls, their results and the
    // turn bookkeeping, none of which anybody said.
    return;
  }

  // Current builds wrap the body in a message envelope; older ones put it
  // at the top level, and some records carry a flat string instead.
  std::string message;
  auto content = record.FindMember("content");
  if (content != record.MemberEnd()) {
    message = transcriptText(content->value);
  }

  if (message.empty()) {
    auto envelope = record.FindMember("message");
    if (envelope != record.MemberEnd() && envelope->value.IsObject()) {
      auto wrapped = envelope->value.FindMember("content");
      if (wrapped != envelope->value.MemberEnd()) {
        message = transcriptText(wrapped->value);
      }
    }
  }

  if (message.empty()) {
    message = stringMember(record, "text");
  }

  if (message.empty()) {
    // A turn that only called a tool has nothing to report.
    return;
  }

  AIAssistantChat chat;
  chat.application = application;
  chat.role = std::move(role);
  chat.message = std::move(message);
  chat.path = path;

  chat.session_id = stringMember(record, "sessionId");
  if (chat.session_id.empty()) {
    chat.session_id = stringMember(record, "conversationId");
  }
  if (chat.session_id.empty()) {
    chat.session_id = session_id;
  }

  chat.timestamp = timestampMember(record, "timestamp");
  if (chat.timestamp == 0) {
    chat.timestamp = timestampMember(record, "createdAt");
  }

  results.push_back(std::move(chat));
}

void parseTranscript(const std::string& content,
                     const std::string& path,
                     const std::string& application,
                     std::vector<AIAssistantChat>& results) {
  auto session_id = fs::path(path).stem().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseTranscriptLine(
          content.substr(start), path, application, session_id, results);
      break;
    }

    parseTranscriptLine(content.substr(start, end - start),
                        path,
                        application,
                        session_id,
                        results);
    start = end + 1;
  }
}

void collectTranscripts(const fs::path& pattern,
                        const std::string& application,
                        std::vector<AIAssistantChat>& results) {
  std::vector<std::string> transcripts;
  resolveFilePattern(pattern, transcripts, GLOB_FILES);

  for (const auto& path : transcripts) {
    // These records rarely name their session, and the file is named
    // after the one it holds.
    auto session_id = fs::path(path).stem().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parseTranscriptLine(line, path, application, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read transcript " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
