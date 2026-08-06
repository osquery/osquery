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
extern const std::string kCopilotApplication;

/**
 * @brief Parse one chat session file written by a VS Code style editor.
 *
 * Editors built on VS Code share its chat session store: a file per
 * conversation holding a list of requests, where a request carries both
 * the prompt the user sent and the response that came back, so a single
 * entry produces up to two rows.
 */
void parseChatSessionFile(const std::string& content,
                          const std::string& path,
                          const std::string& application,
                          std::vector<AIAssistantChat>& results);

/// Reads the chat session files a VS Code style editor writes.
void collectVSCodeChats(const boost::filesystem::path& app_data_root,
                        std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
