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
#include <osquery/tables/applications/ai_assistant_chats/pi.h>
#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/utils/json/json.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kPiApplication{"pi"};

namespace {

/// Entry types of a Pi journal that this table reads.
const std::string kPiSessionEntry{"session"};
const std::string kPiMessageEntry{"message"};

} // namespace

void parsePiSessionLine(const std::string& line,
                        const std::string& path,
                        std::string& session_id,
                        std::vector<AIAssistantChat>& results) {
  auto entry_text = boost::algorithm::trim_copy(line);
  if (entry_text.empty()) {
    return;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(entry_text) || !doc.doc().IsObject()) {
    VLOG(1) << "Skipping unparsable entry in Pi session " << path;
    return;
  }

  const auto& entry = doc.doc();

  auto type = stringMember(entry, "type");
  if (type == kPiSessionEntry) {
    // The opening entry is the one that names the session.
    auto id = stringMember(entry, "id");
    if (!id.empty()) {
      session_id = id;
    }
    return;
  }

  if (type != kPiMessageEntry) {
    // The rest is Pi's own bookkeeping: model changes, compactions and
    // the branch summaries it writes for itself.
    return;
  }

  auto message = entry.FindMember("message");
  if (message == entry.MemberEnd() || !message->value.IsObject()) {
    return;
  }

  // Pi records tool output and shell runs under roles of their own, which
  // transcriptRole leaves alone.
  std::string role;
  if (!transcriptRole(stringMember(message->value, "role"), role)) {
    return;
  }

  auto content = message->value.FindMember("content");
  if (content == message->value.MemberEnd()) {
    return;
  }

  auto text = transcriptText(content->value);
  if (text.empty()) {
    // A turn that only reasoned or called a tool has nothing to report.
    return;
  }

  AIAssistantChat chat;
  chat.application = kPiApplication;
  chat.session_id = session_id;
  chat.role = std::move(role);
  chat.message = std::move(text);
  chat.path = path;

  // The entry carries an ISO 8601 time; the message inside it carries
  // milliseconds since the epoch instead.
  chat.timestamp = timestampMember(entry, "timestamp");
  if (chat.timestamp == 0) {
    chat.timestamp = timestampMember(message->value, "timestamp");
  }

  results.push_back(std::move(chat));
}

void parsePiSession(const std::string& content,
                    const std::string& path,
                    std::vector<AIAssistantChat>& results) {
  auto session_id = fs::path(path).stem().string();

  std::size_t start = 0;
  while (start <= content.size()) {
    auto end = content.find('\n', start);
    if (end == std::string::npos) {
      parsePiSessionLine(content.substr(start), path, session_id, results);
      break;
    }

    parsePiSessionLine(
        content.substr(start, end - start), path, session_id, results);
    start = end + 1;
  }
}

/**
 * @brief Collects the session journals the Pi coding agent writes.
 *
 * @param home User home directory containing the `.pi/agent/sessions`
 * hierarchy.
 * @param results Output collection to which parsed chats are appended.
 */
void collectPiChats(const fs::path& home,
                    std::vector<AIAssistantChat>& results) {
  auto sessions = home / ".pi" / "agent" / "sessions";

  std::vector<std::string> journals;
  resolveFilePattern(sessions / "%.jsonl", journals, GLOB_FILES);
  resolveFilePattern(sessions / "%" / "%.jsonl", journals, GLOB_FILES);
  resolveFilePattern(sessions / "%" / "%" / "%.jsonl", journals, GLOB_FILES);

  for (const auto& path : journals) {
    // The session names itself in its opening entry; until that is read
    // the file name is the best answer available.
    auto session_id = fs::path(path).stem().string();

    auto status = readJsonLines(path, [&](const std::string& line) {
      parsePiSessionLine(line, path, session_id, results);
    });

    if (!status.ok()) {
      VLOG(1) << "Could not read Pi session " << path << ": "
              << status.getMessage();
    }
  }
}

} // namespace tables
} // namespace osquery
