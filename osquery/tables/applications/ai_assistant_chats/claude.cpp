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
#include <osquery/tables/applications/ai_assistant_chats/claude.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kClaudeCodeApplication{"claude_code"};
const std::string kClaudeDesktopApplication{"claude_desktop"};

namespace {

/// Directory Claude Desktop keeps its per-user state under.
const std::string kClaudeDesktopDirectory{"Claude"};
/**
 * The Claude Code CLI replays tool output back to the model as entries
 * that also carry the user role, and injects context of its own the same
 * way. Neither is something a person typed, so only entries that are
 * explicitly human, or that predate the tagging, become rows.
 */
bool isHumanPrompt(const rapidjson::Value& entry) {
  if (boolMember(entry, "isMeta")) {
    return false;
  }

  auto origin = entry.FindMember("origin");
  if (origin != entry.MemberEnd() && origin->value.IsObject()) {
    return stringMember(origin->value, "kind") == "human";
  }

  return true;
}
/**
 * Returns the part of a Claude message the user actually saw or typed.
 * Content is either a plain string or a list of blocks; of the blocks,
 * "thinking" and "tool_use" are the model working rather than answering
 * and "tool_result" is output replayed back to it, so only "text" blocks
 * are kept.
 */
std::string claudeMessageText(const rapidjson::Value& message) {
  auto content = message.FindMember("content");
  if (content == message.MemberEnd()) {
    return "";
  }

  if (content->value.IsString()) {
    return content->value.GetString();
  }

  if (!content->value.IsArray()) {
    return "";
  }

  std::vector<std::string> chunks;
  for (const auto& block : content->value.GetArray()) {
    if (!block.IsObject() || stringMember(block, "type") != "text") {
      continue;
    }

    auto text = stringMember(block, "text");
    if (!text.empty()) {
      chunks.push_back(std::move(text));
    }
  }

  return boost::algorithm::join(chunks, "\n\n");
}
/// Reads every Claude transcript matching one pattern.
void genClaudeTranscripts(const fs::path& pattern,
                          const std::string& application,
                          std::vector<AIAssistantChat>& results) {
  std::vector<std::string> transcripts;
  resolveFilePattern(pattern, transcripts, GLOB_FILES);

  for (const auto& path : transcripts) {
    auto status = readJsonLines(path, [&](const std::string& line) {
      parseClaudeTranscriptLine(line, path, application, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Claude transcript " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace

void parseClaudeTranscriptLine(const std::string& line,
                               const std::string& path,
                               const std::string& application,
                               std::vector<AIAssistantChat>& results) {
  auto entry_text = boost::algorithm::trim_copy(line);
  if (entry_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(entry_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable entry in Claude transcript " << path;
    return;
  }

  const auto& entry = doc.doc();

  // An entry's type doubles as the role of the message it carries.
  auto type = stringMember(entry, "type");
  if (type != kUserRole && type != kAssistantRole) {
    // Everything else in a transcript is session bookkeeping rather than
    // a message: titles, modes, file snapshots and the like.
    return;
  }

  auto message = entry.FindMember("message");
  if (message == entry.MemberEnd() || !message->value.IsObject()) {
    return;
  }

  AIAssistantChat chat;
  chat.application = application;
  chat.timestamp = timestampMember(entry, "timestamp");
  chat.path = path;

  chat.session_id = stringMember(entry, "sessionId");
  if (chat.session_id.empty()) {
    // Every transcript is named after the session it holds.
    chat.session_id = fs::path(path).stem().string();
  }

  if (type == kUserRole && !isHumanPrompt(entry)) {
    return;
  }

  // A typed prompt is a plain string, but one carrying an attachment
  // arrives as blocks instead, and a reply is always blocks. Reading the
  // text out of either covers all of them, and still excludes the tool
  // output the CLI replays under the user role, which carries no text
  // block at all.
  chat.role = type;
  chat.message = claudeMessageText(message->value);

  if (chat.message.empty()) {
    // A turn that only called a tool has nothing to report.
    return;
  }

  results.push_back(std::move(chat));
}
void parseClaudeTranscript(const std::string& content,
                           const std::string& path,
                           const std::string& application,
                           std::vector<AIAssistantChat>& results) {
  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parseClaudeTranscriptLine(
          content.substr(start), path, application, results);
      break;
    }

    parseClaudeTranscriptLine(
        content.substr(start, end - start), path, application, results);
    start = end + 1;
  }
}
/// Reads the transcripts the Claude Code CLI and Claude Desktop leave behind.
void collectClaudeChats(const fs::path& home,
                        const fs::path& app_data_root,
                        std::vector<AIAssistantChat>& results) {
  genClaudeTranscripts(home / ".claude" / "projects" / "%" / "%.jsonl",
                       kClaudeCodeApplication,
                       results);

  // Claude Desktop runs the same engine for the agent sessions it hosts,
  // and gives each one a .claude directory of its own to write to. The
  // conversations held with the model directly are not on disk to read:
  // they live server side, and what the app keeps locally is browser
  // storage rather than a transcript.
  genClaudeTranscripts(app_data_root / kClaudeDesktopDirectory /
                           "local-agent-mode-sessions" / "%" / "%" / "%" /
                           ".claude" / "projects" / "%" / "%.jsonl",
                       kClaudeDesktopApplication,
                       results);
}

} // namespace tables
} // namespace osquery
