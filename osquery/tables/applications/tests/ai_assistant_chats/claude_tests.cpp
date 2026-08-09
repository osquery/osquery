/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/claude.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class ClaudeChatsTest : public ::testing::Test {};

TEST_F(ClaudeChatsTest, test_claude_code_transcript) {
  const std::string transcript =
      R"({"type":"ai-title","sessionId":"session-1","aiTitle":"Some title"})"
      "\n"
      R"({"type":"user","sessionId":"session-1","timestamp":"2026-08-06T06:39:52Z","message":{"role":"user","content":"how do I list processes"}})"
      "\n"
      R"({"type":"assistant","sessionId":"session-1","timestamp":"2026-08-06T06:40:02Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"thinking","thinking":"internal"},{"type":"text","text":"Query the processes table."},{"type":"tool_use","name":"Bash","input":{"command":"ps"}},{"type":"text","text":"Then filter it."}]}})"
      "\n"
      "\n"
      R"({"type":"user","sessionId":"session-1","timestamp":"2026-08-06T06:40:03Z","message":{"role":"user","content":[{"type":"tool_result","content":"PID TTY"}]}})"
      "\n"
      R"({"type":"user","sessionId":"session-1","timestamp":"2026-08-06T06:40:04Z","message":{"role":"user","content":[{"type":"text","text":"and with this file?"},{"type":"image","source":{}}]}})"
      "\n"
      R"({"type":"user","sessionId":"session-1","isMeta":true,"timestamp":"2026-08-06T06:40:04Z","message":{"role":"user","content":"injected context"}})"
      "\n"
      R"({"type":"assistant","sessionId":"session-1","timestamp":"2026-08-06T06:40:05Z","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"ps"}}]}})"
      "\n"
      "not json at all\n";

  std::vector<AIAssistantChat> results;
  parseClaudeTranscript(transcript,
                        "/home/user/.claude/t.jsonl",
                        kClaudeCodeApplication,
                        results);

  // Only what was typed and the reply that had something to say survive:
  // tool results, injected context and tool-only turns are not messages.
  ASSERT_EQ(results.size(), 3U);

  EXPECT_EQ(results[0].application, kClaudeCodeApplication);
  EXPECT_EQ(results[0].session_id, "session-1");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "how do I list processes");
  EXPECT_EQ(results[0].timestamp, 1785998392);
  EXPECT_EQ(results[0].path, "/home/user/.claude/t.jsonl");

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message,
            "Query the processes table.\n\nThen filter it.");
  EXPECT_EQ(results[1].timestamp, 1785998402);

  // A prompt carrying an attachment arrives as blocks rather than as a
  // plain string, and is still what the user typed.
  EXPECT_EQ(results[2].role, "user");
  EXPECT_EQ(results[2].message, "and with this file?");
}

TEST_F(ClaudeChatsTest, test_claude_code_transcript_fallbacks) {
  // Older transcripts tag who wrote an entry with an origin instead, and
  // do not always repeat the session id on every line.
  const std::string transcript =
      R"({"type":"user","origin":{"kind":"human"},"message":{"role":"user","content":"hello"}})"
      "\n"
      R"({"type":"user","origin":{"kind":"tool"},"message":{"role":"user","content":"tool output"}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseClaudeTranscript(transcript,
                        "/home/user/.claude/projects/repo/session-2.jsonl",
                        kClaudeCodeApplication,
                        results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "session-2");
  EXPECT_EQ(results[0].message, "hello");
  EXPECT_EQ(results[0].timestamp, 0);
}

TEST_F(ClaudeChatsTest, test_claude_desktop_transcript) {
  // Claude Desktop hosts the same engine for its agent sessions, so the
  // transcripts are identical and only the application they belong to
  // changes.
  const std::string transcript =
      R"({"type":"user","sessionId":"session-4","message":{"role":"user","content":"summarize this repo"}})";

  std::vector<AIAssistantChat> results;
  parseClaudeTranscript(
      transcript,
      "/home/user/Claude/local-agent-mode-sessions/org/user/local_a/.claude/"
      "projects/outputs/session-4.jsonl",
      kClaudeDesktopApplication,
      results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].application, kClaudeDesktopApplication);
  EXPECT_EQ(results[0].session_id, "session-4");
  EXPECT_EQ(results[0].message, "summarize this repo");
}

} // namespace tables
} // namespace osquery
