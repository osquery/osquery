/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/tables/applications/ai_assistant_chats/windsurf.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kWindsurfApplication{"windsurf"};

/**
 * @brief Collects the chat history Windsurf's Cascade agent leaves on disk.
 *
 * @param home User home directory containing the `.windsurf/transcripts`
 * hierarchy.
 * @param results Output collection to which parsed chats are appended.
 */
void collectWindsurfChats(const fs::path& home,
                          std::vector<AIAssistantChat>& results) {
  // Windsurf writes the same record shape Cursor's agent does. The editor
  // and Devin's desktop app share this directory, so a transcript here is
  // not evidence of which of them was driving.
  auto transcripts = home / ".windsurf" / "transcripts";

  collectTranscripts(transcripts / "%.jsonl", kWindsurfApplication, results);
  collectTranscripts(
      transcripts / "%" / "%.jsonl", kWindsurfApplication, results);
}

} // namespace tables
} // namespace osquery
