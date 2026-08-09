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
extern const std::string kPiApplication;

/**
 * @brief Parses one entry of a Pi session journal.
 *
 * @param line Entry encoded as a JSON line.
 * @param path File the entry was read from.
 * @param session_id Session the journal belongs to, named by its opening
 * entry and used for the entries that follow.
 * @param results Collection to which parsed messages are appended.
 */
void parsePiSessionLine(const std::string& line,
                        const std::string& path,
                        std::string& session_id,
                        std::vector<AIAssistantChat>& results);

/// Parses a whole Pi session journal.
void parsePiSession(const std::string& content,
                    const std::string& path,
                    std::vector<AIAssistantChat>& results);

/// Reads the session journals the Pi coding agent writes.
void collectPiChats(const boost::filesystem::path& home,
                    std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
