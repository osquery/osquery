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

/**
 * Decodes a hexadecimal blob into its raw bytes.
 * @param hex Hexadecimal input with an even number of digits.
 * @param bytes Receives the decoded bytes.
 * @return `true` if the input is valid hexadecimal, `false` otherwise.
 */

/**
 * Extracts a user message or model response from an Antigravity conversation step.
 * @param payload Protobuf-encoded conversation-step data.
 * @param session_id Identifier of the conversation session.
 * @param path Source path of the conversation.
 * @param results Receives the extracted chat entry, when the step contains text.
 */

/**
 * Collects conversations stored by Antigravity under the Gemini directory.
 * @param home User home directory containing the Gemini data.
 * @param results Receives the collected chat entries.
 */
namespace osquery {
namespace tables {

/// The application whose messages this source reports.
extern const std::string kAntigravityApplication;

/**
 * @brief Decode a hex encoded blob back into its bytes.
 *
 * Blobs are read out of SQLite as hex because the protobuf they hold
 * carries NUL bytes, which would cut a text value short. Returns false
 * for anything that is not an even run of hex digits.
 */
bool decodeHexBlob(const std::string& hex, std::string& bytes);

/**
 * @brief Parse one step of an Antigravity conversation.
 *
 * Antigravity stores a conversation as a SQLite database of steps whose
 * payloads are protobuf. Google publishes no schema for them, so the
 * fields below were read off a real conversation and then checked
 * against the schemas the community has extracted from Antigravity's
 * language server, which name them as:
 *
 *   Step.type = 1                              the kind of step
 *   Step.metadata.created_at.seconds = 5.1.1   when it was created
 *   Step.user_input.user_response = 19.2       what the user typed
 *   Step.planner_response.response = 20.1      what the model replied
 *
 * where a step is the user's when Step.type is CORTEX_STEP_TYPE_USER_INPUT
 * (14) and the model's when it is CORTEX_STEP_TYPE_PLANNER_RESPONSE (15).
 *
 * Neither source is authoritative, so treat this as version specific: a
 * step whose payload does not match is skipped rather than guessed at.
 *
 * Steps of any other kind are the agent working (tool calls, artifacts,
 * reasoning), and steps of the right kind that carry no text are turns
 * where nothing was said, so neither becomes a row. Of the fields that
 * sit next to the two read here, planner_response.thinking is the model
 * reasoning rather than answering, and user_input.items repeats the
 * prompt as the scope items it was assembled from.
 */
void parseAntigravityStep(const std::string& payload,
                          const std::string& session_id,
                          const std::string& path,
                          std::vector<AIAssistantChat>& results);

/// Reads the conversations Antigravity keeps under the Gemini directory.
void collectAntigravityChats(const boost::filesystem::path& home,
                             std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
