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
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

/// The application whose messages this source reports.
extern const std::string kGeminiApplication;

/**
 * @brief Parse one line of a Gemini CLI session file.
 *
 * A session is JSON lines: an opening record naming the session, then one
 * record per message carrying an id, a timestamp, a type and its content.
 * Only "user" and "gemini" records are conversation, and the CLI's own
 * rule for what a user record is not (its slash and question mark
 * commands, and the context it injects into a turn) is applied here too.
 *
 * `session_id` carries the id from the opening record across the rest of
 * the file, and should start as a fallback for files without one.
 */
void parseGeminiSessionLine(const std::string& line,
                            const std::string& path,
                            std::string& session_id,
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
