/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/copilot_cli.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class CopilotCliChatsTest : public ::testing::Test {};

TEST_F(CopilotCliChatsTest, test_copilot_cli_events) {
  const std::string events =
      R"({"hookEventName":"SessionStart","sessionId":"9f2","timestamp":"2026-05-03T07:59:00Z"})"
      "\n"
      R"({"hookEventName":"UserPromptSubmitted","sessionId":"9f2","timestamp":"2026-05-03T07:59:23Z","prompt":"list the open ports"})"
      "\n"
      R"({"type":"assistant","sessionId":"9f2","timestamp":"2026-05-03T07:59:30Z","content":"Use the listening_ports table."})"
      "\n"
      R"({"hookEventName":"PreToolUse","sessionId":"9f2","toolName":"ShellCommand","toolArgs":{"command":"ss -lntp"}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseCopilotCliEvents(
      events, "/home/user/.copilot/session-state/9f2/events.jsonl", results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kCopilotCliApplication);
  EXPECT_EQ(results[0].session_id, "9f2");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "list the open ports");
  EXPECT_EQ(results[0].timestamp, 1777795163);

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "Use the listening_ports table.");
}

TEST_F(CopilotCliChatsTest, test_copilot_cli_events_fallbacks) {
  std::vector<AIAssistantChat> results;

  // An event naming neither its session nor its kind the current way.
  parseCopilotCliEvent(R"({"event":"user_prompt_submitted","text":"hello"})",
                       "/home/user/.copilot/session-state/abc/events.jsonl",
                       "abc",
                       results);
  // The tool events and the session's own bookkeeping carry no message.
  for (const auto* event : {
           R"({"hookEventName":"PostToolUse","toolName":"ReadFile"})",
           R"({"hookEventName":"SessionEnd"})",
           R"({"hookEventName":"UserPromptSubmitted","prompt":""})",
           "{not json",
       }) {
    parseCopilotCliEvent(event,
                         "/home/user/.copilot/session-state/abc/events.jsonl",
                         "abc",
                         results);
  }

  ASSERT_EQ(results.size(), 1U);
  // The directory holding the log is named after the session.
  EXPECT_EQ(results[0].session_id, "abc");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "hello");
  EXPECT_EQ(results[0].timestamp, 0);
}

} // namespace tables
} // namespace osquery
