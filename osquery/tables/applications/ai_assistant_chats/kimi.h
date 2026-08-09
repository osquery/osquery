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
extern const std::string kKimiApplication;

/**
 * @brief Parses one record of a Kimi Code wire journal.
 *
 * @param line Record encoded as a JSON line.
 * @param path File the record was read from.
 * @param session_id Session the journal belongs to, taken from its path.
 * @param results Collection to which parsed messages are appended.
 */
void parseKimiWireLine(const std::string& line,
                       const std::string& path,
                       const std::string& session_id,
                       std::vector<AIAssistantChat>& results);

/// Parses a whole Kimi Code wire journal.
void parseKimiWire(const std::string& content,
                   const std::string& path,
                   std::vector<AIAssistantChat>& results);

/// Names the session a Kimi Code wire journal belongs to.
std::string kimiSessionId(const std::string& path);

/// Reads the wire journals Kimi Code writes per session.
void collectKimiChats(const boost::filesystem::path& home,
                      std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
