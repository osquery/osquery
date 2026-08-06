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
extern const std::string kCursorApplication;

/**
 * @brief Parse a single "bubbleId:<session>:<bubble>" record from Cursor.
 *
 * Cursor keeps one row per message in the cursorDiskKV key/value table of
 * its state database; `key` is the row's key and `value` its JSON payload.
 */
void parseCursorBubble(const std::string& key,
                       const std::string& value,
                       const std::string& path,
                       std::vector<AIAssistantChat>& results);

/// Reads the chat history Cursor keeps in its state databases.
void collectCursorChats(const boost::filesystem::path& app_data_root,
                        std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
