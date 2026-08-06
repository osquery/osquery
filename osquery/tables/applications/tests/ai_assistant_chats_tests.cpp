/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/antigravity.h>
#include <osquery/tables/applications/ai_assistant_chats/claude.h>
#include <osquery/tables/applications/ai_assistant_chats/codex.h>
#include <osquery/tables/applications/ai_assistant_chats/cursor.h>
#include <osquery/tables/applications/ai_assistant_chats/gemini.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/tables/applications/ai_assistant_chats/vscode.h>

namespace osquery {
namespace tables {

class AIAssistantChatsTest : public ::testing::Test {};

TEST_F(AIAssistantChatsTest, test_iso8601_to_unix_time) {
  EXPECT_EQ(iso8601ToUnixTime("1970-01-01T00:00:00Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T07:59:23.977Z"), 1777795163);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T07:59:23"), 1777795163);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03 07:59:23Z"), 1777795163);

  // A leap day, and the day after it, in a year divisible by 4.
  EXPECT_EQ(iso8601ToUnixTime("2024-02-29T00:00:00Z"), 1709164800);
  EXPECT_EQ(iso8601ToUnixTime("2024-03-01T00:00:00Z"), 1709251200);

  // 2000 is a leap year, 1900 was not; the day after February in both
  // has to land in the right place.
  EXPECT_EQ(iso8601ToUnixTime("2000-03-01T00:00:00Z"), 951868800);
  EXPECT_EQ(iso8601ToUnixTime("1900-03-01T00:00:00Z"), -2203891200);

  // Anything that is not a timestamp reads as "none recorded".
  EXPECT_EQ(iso8601ToUnixTime(""), 0);
  EXPECT_EQ(iso8601ToUnixTime("yesterday"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-13-03T07:59:23Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("2026-05-03T25:59:23Z"), 0);
  EXPECT_EQ(iso8601ToUnixTime("20260503T075923Z"), 0);
}

TEST_F(AIAssistantChatsTest, test_claude_code_transcript) {
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

TEST_F(AIAssistantChatsTest, test_read_json_lines) {
  // The production path splits entries out of a file as it streams in,
  // so the case worth covering is an entry that straddles the boundary
  // between two reads.
  auto path = boost::filesystem::temp_directory_path() /
              boost::filesystem::unique_path("osquery-jsonl-%%%%.jsonl");

  const std::string filler(4096, 'x');
  const std::size_t kEntries = 100;
  {
    std::ofstream out(path.string(), std::ios::binary);
    for (std::size_t i = 0; i < kEntries; ++i) {
      out << "{\"n\":" << i << ",\"pad\":\"" << filler << "\"}\n";
    }
    // A file does not have to end with a newline, and the last entry is
    // still an entry.
    out << "{\"n\":last}";
  }

  std::vector<std::string> entries;
  auto status = readJsonLines(path.string(), [&](const std::string& line) {
    if (!line.empty()) {
      entries.push_back(line);
    }
  });
  boost::filesystem::remove(path);

  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(entries.size(), kEntries + 1);
  EXPECT_EQ(entries.front().substr(0, 8), "{\"n\":0,\"");
  EXPECT_EQ(entries[kEntries - 1].substr(0, 8), "{\"n\":99,");
  EXPECT_EQ(entries.back(), "{\"n\":last}");
  for (const auto& entry : entries) {
    EXPECT_EQ(entry.find('\n'), std::string::npos);
  }
}

TEST_F(AIAssistantChatsTest, test_claude_code_transcript_fallbacks) {
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

TEST_F(AIAssistantChatsTest, test_claude_desktop_transcript) {
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

TEST_F(AIAssistantChatsTest, test_codex_rollout) {
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

TEST_F(AIAssistantChatsTest, test_codex_rollout_without_session_meta) {
  // A rollout that lost its opening entry still names its session in the
  // file it was written to.
  const std::string rollout =
      R"({"timestamp":"2026-08-06T07:30:54.606Z","type":"event_msg","payload":{"type":"user_message","message":"hello"}})";

  std::vector<AIAssistantChat> results;
  parseCodexRollout(rollout, "/home/user/.codex/rollout-abc.jsonl", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "rollout-abc");
}

TEST_F(AIAssistantChatsTest, test_gemini_session) {
  const std::string session =
      R"({"sessionId":"c0ffee","projectHash":"9f2b","startTime":"2026-08-06T09:00:00.000Z"})"
      "\n"
      R"({"id":"m1","timestamp":"2026-08-06T09:00:04.000Z","type":"user","content":"where does this config get loaded"})"
      "\n"
      R"({"id":"m2","timestamp":"2026-08-06T09:00:09.000Z","type":"gemini","model":"gemini-3-pro","content":[{"text":"It is read in "},{"text":"config.ts."}],"toolCalls":[{"name":"read_file"}]})"
      "\n"
      R"({"id":"m3","timestamp":"2026-08-06T09:00:12.000Z","type":"info","content":"Model switched."})"
      "\n"
      R"({"id":"m4","timestamp":"2026-08-06T09:00:20.000Z","type":"user","content":{"text":"and the defaults?"}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseGeminiSession(
      session, "/home/user/.gemini/tmp/9f2b/chats/c0ffee.jsonl", results);

  // The notice the CLI printed is not something either side said.
  ASSERT_EQ(results.size(), 3U);

  EXPECT_EQ(results[0].application, kGeminiApplication);
  EXPECT_EQ(results[0].session_id, "c0ffee");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "where does this config get loaded");
  EXPECT_EQ(results[0].timestamp, 1786006804);
  EXPECT_EQ(results[0].path, "/home/user/.gemini/tmp/9f2b/chats/c0ffee.jsonl");

  // A reply arrives as a list of parts and has to be stitched back up.
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "It is read in config.ts.");

  EXPECT_EQ(results[2].role, "user");
  EXPECT_EQ(results[2].message, "and the defaults?");
}

TEST_F(AIAssistantChatsTest, test_gemini_session_skipped) {
  // Commands the CLI handles itself and context it injects into a turn
  // are not conversation, by the CLI's own definition. A session that
  // never opened with a metadata record still names itself by its file.
  const std::string session =
      R"({"id":"m1","timestamp":"2026-08-06T09:00:04.000Z","type":"user","content":"/chat save work"})"
      "\n"
      R"({"id":"m2","timestamp":"2026-08-06T09:00:05.000Z","type":"user","content":"?"})"
      "\n"
      R"({"id":"m3","timestamp":"2026-08-06T09:00:06.000Z","type":"user","content":"<session_context>cwd: /repo</session_context>"})"
      "\n"
      R"({"id":"m4","timestamp":"2026-08-06T09:00:07.000Z","type":"user","content":"<hook_context>pre</hook_context>"})"
      "\n"
      R"({"id":"m5","timestamp":"2026-08-06T09:00:08.000Z","type":"gemini","content":[]})"
      "\n"
      R"({"$rewindTo":"m1"})"
      "\n"
      R"({"id":"m6","timestamp":"2026-08-06T09:00:30.000Z","type":"user","content":"actually, list the tables"})"
      "\n"
      R"({"id":"m7","timestamp":"2026-08-06T09:00:40.000Z","type":"user","content":"/etc/hosts is wrong, can you fix it"})"
      "\n"
      "not json\n";

  std::vector<AIAssistantChat> results;
  parseGeminiSession(
      session,
      "/home/user/.gemini/tmp/9f2b/chats/session-1754470800.jsonl",
      results);

  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].session_id, "session-1754470800");
  EXPECT_EQ(results[0].message, "actually, list the tables");

  // A prompt that opens by naming a file is still a prompt, even though
  // it starts with the character a command starts with.
  EXPECT_EQ(results[1].message, "/etc/hosts is wrong, can you fix it");
}

TEST_F(AIAssistantChatsTest, test_cursor_bubble) {
  std::vector<AIAssistantChat> results;

  parseCursorBubble(
      "bubbleId:008b32b2-1057-43c8-b80e-cf1858800910:034fa81c-aff4-4227-8a5c-"
      "1f371e8592a8",
      R"({"type":1,"text":"build me a stock monitor","createdAt":"2026-05-03T07:59:59Z"})",
      "/home/user/state.vscdb",
      results);
  parseCursorBubble(
      "bubbleId:008b32b2-1057-43c8-b80e-cf1858800910:0f87570d-6c32-4b17-acab-"
      "99f4894a4abb",
      R"({"type":2,"text":"Here is one approach.","createdAt":1777795163977})",
      "/home/user/state.vscdb",
      results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kCursorApplication);
  EXPECT_EQ(results[0].session_id, "008b32b2-1057-43c8-b80e-cf1858800910");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "build me a stock monitor");
  EXPECT_EQ(results[0].timestamp, 1777795199);
  EXPECT_EQ(results[0].path, "/home/user/state.vscdb");

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "Here is one approach.");
  // Written in milliseconds by this build of Cursor.
  EXPECT_EQ(results[1].timestamp, 1777795163);
}

TEST_F(AIAssistantChatsTest, test_cursor_bubble_skipped) {
  std::vector<AIAssistantChat> results;

  // A step that only ran a tool leaves no text behind.
  parseCursorBubble("bubbleId:session:bubble",
                    R"({"type":2,"text":""})",
                    "/home/user/state.vscdb",
                    results);
  // An author Cursor does not describe as a person or the model.
  parseCursorBubble("bubbleId:session:bubble",
                    R"({"type":7,"text":"something"})",
                    "/home/user/state.vscdb",
                    results);
  // Rows of the key/value store that are not messages at all.
  parseCursorBubble("composerData:session",
                    R"({"type":1,"text":"something"})",
                    "/home/user/state.vscdb",
                    results);
  parseCursorBubble("bubbleId:bubble",
                    R"({"type":1,"text":"something"})",
                    "/home/user/state.vscdb",
                    results);
  parseCursorBubble("bubbleId:session:bubble",
                    "{not json",
                    "/home/user/state.vscdb",
                    results);

  EXPECT_TRUE(results.empty());
}

TEST_F(AIAssistantChatsTest, test_copilot_chat_session) {
  const std::string session =
      R"({
        "version": 3,
        "sessionId": "97ac4e9d-9b41-4d1c-8f3f-04eec2d6c7f3",
        "creationDate": 1786077592000,
        "requests": [
          {
            "requestId": "request_1",
            "timestamp": 1786077592000,
            "message": {"text": "explain this function"},
            "response": [{"value": "It reads "}, {"value": "a file."}]
          },
          {
            "requestId": "request_2",
            "timestamp": 1786077600000,
            "message": {"text": "and this one?"},
            "response": []
          }
        ]
      })";

  std::vector<AIAssistantChat> results;
  parseChatSessionFile(
      session, "/home/user/chatSessions/a.json", kCopilotApplication, results);

  // The second request never got an answer, so it only produces a prompt.
  ASSERT_EQ(results.size(), 3U);

  EXPECT_EQ(results[0].application, kCopilotApplication);
  EXPECT_EQ(results[0].session_id, "97ac4e9d-9b41-4d1c-8f3f-04eec2d6c7f3");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "explain this function");
  EXPECT_EQ(results[0].timestamp, 1786077592);
  EXPECT_EQ(results[0].path, "/home/user/chatSessions/a.json");

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "It reads a file.");

  EXPECT_EQ(results[2].role, "user");
  EXPECT_EQ(results[2].message, "and this one?");
}

TEST_F(AIAssistantChatsTest, test_copilot_chat_session_fallbacks) {
  // A session file that names itself only by its filename, and a request
  // that stores its prompt and answer as plain strings.
  const std::string session =
      R"({"requests":[{"message":"a prompt","response":"an answer"}]})";

  std::vector<AIAssistantChat> results;
  parseChatSessionFile(session,
                       "/home/user/chatSessions/session-3.json",
                       kCopilotApplication,
                       results);

  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].session_id, "session-3");
  EXPECT_EQ(results[0].message, "a prompt");
  EXPECT_EQ(results[0].timestamp, 0);
  EXPECT_EQ(results[1].session_id, "session-3");
  EXPECT_EQ(results[1].message, "an answer");
}

namespace {

// Steps shaped like the ones a real Antigravity conversation holds, hex
// encoded the way they come back out of SQLite. Decoded, each carries
// field 1 as the kind of step, field 5.1.1 as the second it was created,
// and the text at 19.2 for the user or 20.1 for the model.
const std::string kAntigravityUserStepHex =
    "080E20032A0C0A0808ABE6D0D306100018049A0162122E73686F77206D652068"
    "6F7720796F756420696D706C656D656E7420616E206167656E74696320776F72"
    "6B666C6F771A300A2E73686F77206D6520686F7720796F756420696D706C656D"
    "656E7420616E206167656E74696320776F726B666C6F77";

const std::string kAntigravityAssistantStepHex =
    "080F20032A0C0A0808B0E6D0D30610001804A2015E0A26492068617665206372"
    "656174656420616E20496D706C656D656E746174696F6E20506C616E2E320C62"
    "6F742D30303030303030304226492068617665206372656174656420616E2049"
    "6D706C656D656E746174696F6E20506C616E2E";

// A step the agent took rather than said, and a prompt that only
// attached a file, neither of which is a message.
const std::string kAntigravityToolStepHex =
    "080520032A0C0A0808FEE6D0D30610001804A2010E320C626F742D3030303030"
    "303030";

const std::string kAntigravityAttachmentStepHex =
    "080E20032A0C0A0808F6E6D0D306100018049A010F620D66696C653A2F2F2F74"
    "6D702F78";

std::string decoded(const std::string& hex) {
  std::string bytes;
  EXPECT_TRUE(decodeHexBlob(hex, bytes));
  return bytes;
}

} // namespace

TEST_F(AIAssistantChatsTest, test_decode_hex_blob) {
  std::string bytes;

  ASSERT_TRUE(decodeHexBlob("080E2003", bytes));
  EXPECT_EQ(bytes, std::string("\x08\x0e\x20\x03", 4));

  // A blob is allowed to be empty, and NUL bytes are the reason the hex
  // detour exists at all.
  ASSERT_TRUE(decodeHexBlob("", bytes));
  EXPECT_TRUE(bytes.empty());
  ASSERT_TRUE(decodeHexBlob("0041", bytes));
  EXPECT_EQ(bytes, std::string("\x00\x41", 2));

  EXPECT_FALSE(decodeHexBlob("080", bytes));
  EXPECT_FALSE(decodeHexBlob("08zz", bytes));
  // Everything a general string to number conversion would have taken.
  EXPECT_FALSE(decodeHexBlob("08 0E 20", bytes));
  EXPECT_FALSE(decodeHexBlob("0x08", bytes));
  EXPECT_FALSE(decodeHexBlob("-1", bytes));
}

TEST_F(AIAssistantChatsTest, test_antigravity_conversation) {
  const std::string path =
      "/home/user/.gemini/antigravity/conversations/a1b2c3d4.db";

  std::vector<AIAssistantChat> results;
  parseAntigravityStep(
      decoded(kAntigravityUserStepHex), "a1b2c3d4", path, results);
  parseAntigravityStep(
      decoded(kAntigravityAssistantStepHex), "a1b2c3d4", path, results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kAntigravityApplication);
  EXPECT_EQ(results[0].session_id, "a1b2c3d4");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message,
            "show me how youd implement an agentic workflow");
  EXPECT_EQ(results[0].timestamp, 1786000171);
  EXPECT_EQ(results[0].path, path);

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "I have created an Implementation Plan.");
  EXPECT_EQ(results[1].timestamp, 1786000176);
}

TEST_F(AIAssistantChatsTest, test_antigravity_step_skipped) {
  std::vector<AIAssistantChat> results;

  // The agent working, and a prompt that only attached a file.
  parseAntigravityStep(
      decoded(kAntigravityToolStepHex), "a1b2c3d4", "/x.db", results);
  parseAntigravityStep(
      decoded(kAntigravityAttachmentStepHex), "a1b2c3d4", "/x.db", results);

  // Payloads that are not the message they were taken for. A step of a
  // future Antigravity is skipped, never guessed at.
  parseAntigravityStep("", "a1b2c3d4", "/x.db", results);
  parseAntigravityStep(
      std::string("\x08\x0e\x9a\x01\x7f", 5), "a1b2c3d4", "/x.db", results);
  parseAntigravityStep("not protobuf at all", "a1b2c3d4", "/x.db", results);

  EXPECT_TRUE(results.empty());
}

TEST_F(AIAssistantChatsTest, test_chat_session_nested_response_parts) {
  // Not every kind of response part keeps its text at the top level.
  const std::string session =
      R"({"sessionId":"7f","requests":[{"message":{"text":"why?"},"response":[)"
      R"({"value":"Because "},{"kind":"markdownContent","content":{"value":"of the cache."}}]}]})";

  std::vector<AIAssistantChat> results;
  parseChatSessionFile(
      session, "/home/user/chatSessions/7f.json", kCopilotApplication, results);

  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "Because of the cache.");
}

TEST_F(AIAssistantChatsTest, test_chat_session_journal) {
  // Newer editors journal a session rather than rewriting it: a snapshot
  // of the session as it stood, then the changes made to it. A record
  // sets the value at a path, or extends the list at one.
  const std::string journal =
      R"({"kind":0,"v":{"version":3,"sessionId":"1d830b57","creationDate":1786006635121,"requests":[]}})"
      "\n"
      R"({"kind":1,"k":["customTitle"],"v":"a title"})"
      "\n"
      R"({"kind":2,"k":["requests"],"v":[{"message":{"text":"what does this do?"},"timestamp":1786006695282,"response":[]}]})"
      "\n"
      R"({"kind":2,"k":["requests",0,"response"],"v":[{"kind":"thinking","value":["reasoning the user did not ask for"]},{"supportHtml":false,"value":"It reads "},{"kind":"toolInvocationSerialized","toolId":"read_file"}]})"
      "\n"
      R"({"kind":1,"k":["requests",0,"elapsedMs"],"v":8391})"
      "\n"
      R"({"kind":2,"k":["requests",0,"response"],"v":[{"kind":"markdownContent","content":{"value":"a file."}}]})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseChatSessionFile(journal,
                       "/home/user/emptyWindowChatSessions/1d830b57.jsonl",
                       kCopilotApplication,
                       results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kCopilotApplication);
  EXPECT_EQ(results[0].session_id, "1d830b57");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "what does this do?");
  EXPECT_EQ(results[0].timestamp, 1786006695);

  // The reply is stitched from the parts it streamed in as, whether the
  // text sits at the top of a part or one level down. What the model was
  // thinking, and the tools it called, are not the reply.
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "It reads a file.");
}

TEST_F(AIAssistantChatsTest, test_chat_session_journal_without_snapshot) {
  // Lines that never opened with a snapshot are not a journal, and are
  // not a session file either.
  std::vector<AIAssistantChat> results;
  parseChatSessionFile(
      R"({"kind":1,"k":["customTitle"],"v":"a title"})"
      "\n"
      R"({"kind":2,"k":["requests"],"v":[{"message":{"text":"hello"}}]})"
      "\n",
      "/home/user/emptyWindowChatSessions/x.jsonl",
      kCopilotApplication,
      results);

  EXPECT_TRUE(results.empty());
}

TEST_F(AIAssistantChatsTest, test_chat_session_malformed) {
  std::vector<AIAssistantChat> results;

  parseChatSessionFile(
      "not json", "/home/user/a.json", kCopilotApplication, results);
  parseChatSessionFile("[]", "/home/user/a.json", kCopilotApplication, results);
  parseChatSessionFile(R"({"requests":"none"})",
                       "/home/user/a.json",
                       kCopilotApplication,
                       results);
  parseChatSessionFile(R"({"requests":[{"message":{}}]})",
                       "/home/user/a.json",
                       kCopilotApplication,
                       results);

  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
