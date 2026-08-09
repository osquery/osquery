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
extern const std::string kWindsurfApplication;

/// Reads the transcripts Windsurf's Cascade agent writes per session.
void collectWindsurfChats(const boost::filesystem::path& home,
                          std::vector<AIAssistantChat>& results);

} // namespace tables
} // namespace osquery
