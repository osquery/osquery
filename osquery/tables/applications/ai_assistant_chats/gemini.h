/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

/// The application whose messages this source reports.
extern const std::string kGeminiApplication;

/**
 * @brief A Gemini CLI session as its file is read.
 *
 * The messages are held rather than reported one by one, because the CLI
 * can restate a session's whole history partway through the file and a
 * prompt can reach the file that way and no other. Each is kept under
 * the id it was recorded with, so that a record repeated under an id
 * already seen revises it rather than doubling it.
 */
struct GeminiSession final {
  std::string session_id;
  std::vector<std::pair<std::string, AIAssistantChat>> messages;
};

/**
 * @brief Parse one line of a Gemini CLI session file into `session`.
 *
 * A session is JSON lines: an opening record naming the session, then a
 * record per message carrying an id, a timestamp, a type and its
 * content, and records revising the session's metadata. Only "user" and
 * "gemini" records are conversation, and the CLI's own rule for what a
 * user record is not (its slash and question mark commands, and the
 * context it injects into a turn) is applied here too.
 *
 * A metadata record carrying "messages" is the CLI restating the whole
 * history, and replaces what was read before it, which is how the CLI
 * itself reads one. A record rewinding the session is not honoured: a
 * turn the user later took back was still typed and sent.
 *
 * `session.session_id` should start as a fallback for a file whose
 * opening record is missing.
 */
void parseGeminiSessionLine(const std::string& line,
                            const std::string& path,
                            GeminiSession& session);

/// Moves a finished session's messages into `results`.
void finishGeminiSession(GeminiSession& session,
                         std::vector<AIAssistantChat>& results);

/// Parse a whole Gemini CLI session file, one record per line.
void parseGeminiSession(const std::string& content,
                        const std::string& path,
                        std::vector<AIAssistantChat>& results);

/// Reads the sessions the Gemini CLI records.
void collectGeminiChats(const boost::filesystem::path& home,
                        std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
