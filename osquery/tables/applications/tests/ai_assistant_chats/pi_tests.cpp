/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/pi.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class PiChatsTest : public ::testing::Test {};

TEST_F(PiChatsTest, test_pi_session) {
  const std::string session =
      R"({"type":"session","version":1,"id":"01H8","cwd":"/home/user/src","timestamp":"2026-05-03T07:59:00Z"})"
      "\n"
      R"({"type":"message","timestamp":"2026-05-03T07:59:23Z","message":{"role":"user","content":[{"type":"text","text":"why is the build slow"}]}})"
      "\n"
      R"({"type":"message","message":{"role":"assistant","timestamp":1777795163977,"content":[{"type":"thinking","thinking":"internal"},{"type":"text","text":"The link step dominates."},{"type":"toolCall","name":"bash"}]}})"
      "\n"
      R"({"type":"message","message":{"role":"toolResult","toolName":"bash","toolCallId":"1"}})"
      "\n"
      R"({"type":"compaction","summary":"earlier turns"})"
      "\n";

  std::vector<AIAssistantChat> results;
  parsePiSession(session, "/home/user/.pi/agent/sessions/01H8.jsonl", results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kPiApplication);
  EXPECT_EQ(results[0].session_id, "01H8");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "why is the build slow");
  EXPECT_EQ(results[0].timestamp, 1777795163);

  EXPECT_EQ(results[1].role, "assistant");
  // The reasoning and the tool call are not what the model said.
  EXPECT_EQ(results[1].message, "The link step dominates.");
  // The entry carried no time, so the message inside it answered instead.
  EXPECT_EQ(results[1].timestamp, 1777795163);
}

} // namespace tables
} // namespace osquery
