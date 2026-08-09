/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/codex.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class CodexChatsTest : public ::testing::Test {};

TEST_F(CodexChatsTest, test_codex_rollout) {
  const std::string rollout =
      R"({"timestamp":"2026-08-06T07:30:52.259Z","type":"session_meta","payload":{"session_id":"019fd5fb-6ab4","cwd":"/repo","originator":"Codex Desktop"}})"
      "\n"
      R"({"timestamp":"2026-08-06T07:30:52.259Z","type":"event_msg","payload":{"type":"task_started","turn_id":"019fd5fb-6cda"}})"
      "\n"
      R"({"timestamp":"2026-08-06T07:30:54.589Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<recommended_plugins>injected by codex</recommended_plugins>"}]}})"
      "\n"
      R"({"timestamp":"2026-08-06T07:30:54.606Z","type":"event_msg","payload":{"type":"user_message","message":"test\n","images":[]}})"
      "\n"
      R"({"timestamp":"2026-08-06T07:30:56.000Z","type":"event_msg","payload":{"type":"agent_message","message":"Test received.","phase":"final"}})"
      "\n"
      R"({"timestamp":"2026-08-06T07:30:57.000Z","type":"event_msg","payload":{"type":"token_count","info":{}}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseCodexRollout(
      rollout,
      "/home/user/.codex/sessions/2026/08/06/rollout-2026-08-06T10-30-51.jsonl",
      results);

  // The context Codex injects on the user's behalf is not a message, and
  // neither is the bookkeeping the session emits around every turn.
  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kCodexApplication);
  EXPECT_EQ(results[0].session_id, "019fd5fb-6ab4");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "test\n");
  EXPECT_EQ(results[0].timestamp, 1786001454);

  EXPECT_EQ(results[1].session_id, "019fd5fb-6ab4");
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "Test received.");
}

TEST_F(CodexChatsTest, test_codex_rollout_without_session_meta) {
  // A rollout that lost its opening entry still names its session in the
  // file it was written to.
  const std::string rollout =
      R"({"timestamp":"2026-08-06T07:30:54.606Z","type":"event_msg","payload":{"type":"user_message","message":"hello"}})";

  std::vector<AIAssistantChat> results;
  parseCodexRollout(rollout, "/home/user/.codex/rollout-abc.jsonl", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "rollout-abc");
}

} // namespace tables
} // namespace osquery
