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
extern const std::string kCopilotCliApplication;

/**
 * @brief Parses one event from a Copilot CLI session's event log.
 *
 * @param line Event encoded as a JSON line.
 * @param path File the event was read from.
 * @param session_id Session to attribute the message to when the event
 * does not name one.
 * @param results Collection to which parsed messages are appended.
 */
void parseCopilotCliEvent(const std::string& line,
                          const std::string& path,
                          const std::string& session_id,
                          std::vector<AIAssistantChat>& results);

/// Parses a whole Copilot CLI event log.
void parseCopilotCliEvents(const std::string& content,
                           const std::string& path,
                           std::vector<AIAssistantChat>& results);

/// Reads the event logs the Copilot CLI keeps per session.
void collectCopilotCliChats(const boost::filesystem::path& home,
                            std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
