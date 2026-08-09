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

#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

/**
 * @brief Reads the visible text out of a transcript content value.
 *
 * Accepts the shapes this family of stores writes: a plain string, a
 * single text block, or an array of typed blocks of which only the text
 * ones are the message. Blocks are joined by a blank line, as a reply
 * split across several of them reads as one message.
 */
std::string transcriptText(const rapidjson::Value& content);

/**
 * @brief Maps a transcript role name onto the two roles this table reports.
 *
 * @return true when the name is one of the roles a message can have, false
 * for the tool and bookkeeping records that share the same files.
 */
bool transcriptRole(const std::string& name, std::string& role);

/**
 * @brief Parses one line of a role-and-content JSON Lines transcript.
 *
 * Cursor and Windsurf write the same record shape, so both read through
 * here: a record names its role, carries its text either at the top level
 * or inside a message envelope, and leaves everything else to the tool
 * bookkeeping records this skips.
 *
 * @param line Transcript record to parse.
 * @param path File the record was read from.
 * @param application Application identifier to record on the message.
 * @param session_id Session to attribute the message to when the record
 * does not name one of its own.
 * @param results Collection to which parsed messages are appended.
 */
void parseTranscriptLine(const std::string& line,
                         const std::string& path,
                         const std::string& application,
                         const std::string& session_id,
                         std::vector<AIAssistantChat>& results);

/**
 * @brief Parses a whole role-and-content transcript.
 *
 * @param content Transcript content in JSON Lines format.
 * @param path File the transcript was read from.
 * @param application Application identifier to record on the messages.
 * @param results Collection to which parsed messages are appended.
 */
void parseTranscript(const std::string& content,
                     const std::string& path,
                     const std::string& application,
                     std::vector<AIAssistantChat>& results);

/**
 * @brief Reads every transcript matching a pattern into `results`.
 *
 * @param pattern Path pattern the transcripts are found by.
 * @param application Application identifier to record on the messages.
 * @param results Collection to which parsed messages are appended.
 */
void collectTranscripts(const boost::filesystem::path& pattern,
                        const std::string& application,
                        std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
