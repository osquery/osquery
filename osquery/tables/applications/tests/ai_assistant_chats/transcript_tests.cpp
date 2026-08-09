/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/cursor.h>
#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/tables/applications/ai_assistant_chats/windsurf.h>

namespace osquery {
namespace tables {

class TranscriptChatsTest : public ::testing::Test {};

TEST_F(TranscriptChatsTest, test_agent_transcript) {
  // The shape Cursor's agent writes: a role, and the body inside a
  // message envelope alongside the tool calls of the same turn.
  const std::string transcript =
      R"({"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nbuild a stock monitor\n</user_query>"}]}})"
      "\n"
      R"({"role":"assistant","message":{"content":[{"type":"text","text":"Scaffolding a monitor."},{"type":"tool_use","name":"Write","input":{"path":"a.ts"}},{"type":"text","text":"Done."}]}})"
      "\n"
      R"({"role":"assistant","message":{"content":[{"type":"tool_use","name":"Glob","input":{}}]}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseTranscript(transcript,
                  "/home/user/.cursor/projects/p/agent-transcripts/s/s.jsonl",
                  kCursorApplication,
                  results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kCursorApplication);
  // Nothing in the record names the session, so the file does.
  EXPECT_EQ(results[0].session_id, "s");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message,
            "<user_query>\nbuild a stock monitor\n</user_query>");
  // These records carry no time of their own.
  EXPECT_EQ(results[0].timestamp, 0);

  EXPECT_EQ(results[1].role, "assistant");
  // The text of one turn reads as one message, and the tool call between
  // the two halves is not part of it.
  EXPECT_EQ(results[1].message, "Scaffolding a monitor.\n\nDone.");
}

TEST_F(TranscriptChatsTest, test_agent_transcript_shapes) {
  std::vector<AIAssistantChat> results;

  // A record that types itself rather than naming a role, with the body
  // at the top level and a session and time of its own.
  parseTranscriptLine(
      R"({"type":"user","sessionId":"abc","timestamp":"2026-05-03T07:59:23Z","content":"hello"})",
      "/home/user/a.jsonl",
      kWindsurfApplication,
      "fallback",
      results);
  // A flat string body, timed the way older builds wrote it.
  parseTranscriptLine(
      R"({"role":"model","conversationId":"def","createdAt":1777795163977,"text":"hi"})",
      "/home/user/a.jsonl",
      kWindsurfApplication,
      "fallback",
      results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kWindsurfApplication);
  EXPECT_EQ(results[0].session_id, "abc");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "hello");
  EXPECT_EQ(results[0].timestamp, 1777795163);

  EXPECT_EQ(results[1].session_id, "def");
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "hi");
  EXPECT_EQ(results[1].timestamp, 1777795163);
}

TEST_F(TranscriptChatsTest, test_agent_transcript_skipped) {
  std::vector<AIAssistantChat> results;

  for (const auto* record : {
           // The tool bookkeeping that shares the file.
           R"({"role":"tool","message":{"content":[{"type":"text","text":"ok"}]}})",
           R"({"type":"tool_result","content":"ok"})",
           R"({"type":"turn_ended"})",
           // A turn that said nothing.
           R"({"role":"assistant","message":{"content":[]}})",
           R"({"role":"user","content":""})",
           // Not a record at all.
           "{not json",
           "[]",
           "",
       }) {
    parseTranscriptLine(
        record, "/home/user/a.jsonl", kCursorApplication, "s", results);
  }

  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
