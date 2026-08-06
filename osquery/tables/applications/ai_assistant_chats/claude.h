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

/// The applications whose messages this source reports.
extern const std::string kClaudeCodeApplication;
extern const std::string kClaudeDesktopApplication;

/**
 * @brief Parse one line of a Claude transcript.
 *
 * Transcripts are JSON lines; each line is one entry tagged with a "type".
 * Only entries a human typed and the model's visible replies become rows,
 * everything else (tool plumbing, session metadata) is skipped. Malformed
 * lines are skipped rather than treated as an error, since the format is
 * internal to the CLI and changes between releases. Claude Desktop runs
 * the same engine for its agent sessions and writes the same transcripts,
 * so the application the rows belong to is passed in by the caller.
 */
void parseClaudeTranscriptLine(const std::string& line,
                               const std::string& path,
                               const std::string& application,
                               std::vector<AIAssistantChat>& results);

/// Parse a whole Claude transcript, one entry per line.
void parseClaudeTranscript(const std::string& content,
                           const std::string& path,
                           const std::string& application,
                           std::vector<AIAssistantChat>& results);

/// Reads the transcripts the Claude Code CLI and Claude Desktop leave behind.
void collectClaudeChats(const boost::filesystem::path& home,
                        const boost::filesystem::path& app_data_root,
                        std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
