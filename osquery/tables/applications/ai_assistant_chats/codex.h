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
extern const std::string kCodexApplication;

/**
 * @brief Parse one line of a Codex rollout.
 *
 * A rollout is JSON lines of {timestamp, type, payload}. The messages a
 * person saw are the "event_msg" entries: user_message for what was
 * typed, agent_message for what came back. The parallel "response_item"
 * entries are the raw conversation held with the model, which mixes in
 * the instructions and context Codex supplies on the user's behalf, so
 * they are not read.
 *
 * `session_id` carries the id from the rollout's opening entry across the
 * rest of the file, and should start as a fallback for the files that do
 * not have one.
 */
void parseCodexRolloutLine(const std::string& line,
                           const std::string& path,
                           std::string& session_id,
                           std::vector<AIAssistantChat>& results);

/// Parse a whole Codex rollout, one entry per line.
void parseCodexRollout(const std::string& content,
                       const std::string& path,
                       std::vector<AIAssistantChat>& results);

/// Reads the rollouts Codex writes, from the CLI and its editor clients.
void collectCodexChats(const boost::filesystem::path& home,
                       std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
