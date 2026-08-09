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
#include <osquery/tables/applications/ai_assistant_chats/copilot_cli.h>
#include <osquery/tables/applications/ai_assistant_chats/cursor.h>
#include <osquery/tables/applications/ai_assistant_chats/gemini.h>
#include <osquery/tables/applications/ai_assistant_chats/kimi.h>
#include <osquery/tables/applications/ai_assistant_chats/pi.h>
#include <osquery/tables/applications/ai_assistant_chats/transcript.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/tables/applications/ai_assistant_chats/vscode.h>
#include <osquery/tables/applications/ai_assistant_chats/windsurf.h>

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

TEST_F(AIAssistantChatsTest, test_gemini_session_checkpoint) {
  // The CLI can restate a session's whole history in one record, and a
  // prompt can reach the file that way and no other. It replaces what
  // came before it, the way the CLI itself reads one, so a prompt that
  // appears both as its own record and in the checkpoint is one row.
  const std::string session =
      R"({"sessionId":"c0ffee","projectHash":"9f2b"})"
      "\n"
      R"({"id":"m1","timestamp":"2026-08-06T09:00:04.000Z","type":"user","content":"a prompt that was later restated"})"
      "\n"
      R"({"$set":{"lastUpdated":"2026-08-06T09:01:00.000Z","messages":[)"
      R"({"id":"m1","timestamp":"2026-08-06T09:00:04.000Z","type":"user","content":[{"text":"a prompt that was later restated"}]},)"
      R"({"id":"m2","timestamp":"2026-08-06T09:00:09.000Z","type":"gemini","content":[{"text":"an answer only the checkpoint holds"}]},)"
      R"({"id":"m3","timestamp":"2026-08-06T09:00:10.000Z","type":"user","content":[{"text":"<session_context>cwd: /repo</session_context>"}]})"
      R"(]}})"
      "\n"
      R"({"$set":{"lastUpdated":"2026-08-06T09:02:00.000Z"}})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseGeminiSession(
      session, "/home/user/.gemini/tmp/9f2b/chats/c0ffee.jsonl", results);

  // The context the CLI injects is not a prompt, wherever it is written.
  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].session_id, "c0ffee");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "a prompt that was later restated");
  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "an answer only the checkpoint holds");
}

TEST_F(AIAssistantChatsTest, test_gemini_session_revises_by_id) {
  // A record repeated under an id already seen revises that message
  // rather than doubling it.
  const std::string session =
      R"({"sessionId":"c0ffee","projectHash":"9f2b"})"
      "\n"
      R"({"id":"m1","type":"user","content":"first draft"})"
      "\n"
      R"({"id":"m1","type":"user","content":"what was actually sent"})"
      "\n";

  std::vector<AIAssistantChat> results;
  parseGeminiSession(
      session, "/home/user/.gemini/tmp/9f2b/chats/c0ffee.jsonl", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].message, "what was actually sent");
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

TEST_F(AIAssistantChatsTest, test_agent_transcript) {
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

TEST_F(AIAssistantChatsTest, test_agent_transcript_shapes) {
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

TEST_F(AIAssistantChatsTest, test_agent_transcript_skipped) {
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

TEST_F(AIAssistantChatsTest, test_copilot_cli_events) {
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

TEST_F(AIAssistantChatsTest, test_copilot_cli_events_fallbacks) {
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

TEST_F(AIAssistantChatsTest, test_pi_session) {
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
  parsePiSession(
      session, "/home/user/.pi/agent/sessions/01H8.jsonl", results);

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

TEST_F(AIAssistantChatsTest, test_kimi_wire) {
  const std::string wire =
      R"({"type":"metadata","protocol_version":"1","time":1777795100000,"cwd":"/home/user/src"})"
      "\n"
      R"({"type":"turn.prompt","time":1777795163977,"origin":{"kind":"user"},"input":[{"type":"text","text":"add a retry"}]})"
      "\n"
      R"({"type":"context.append_loop_event","time":1777795170000,"event":{"type":"content.part","part":{"type":"think","think":"internal"}}})"
      "\n"
      R"({"type":"context.append_loop_event","time":1777795170000,"event":{"type":"content.part","part":{"type":"text","text":"Wrapping the call."}}})"
      "\n"
      R"({"type":"context.append_loop_event","time":1777795180000,"event":{"type":"tool.call","name":"Edit","toolCallId":"1"}})"
      "\n"
      R"({"type":"context.append_message","time":1777795163977,"input":[{"type":"text","text":"add a retry"}]})"
      "\n";

  const std::string path =
      "/home/user/.kimi-code/sessions/2026-05-03/7c1/agents/main/wire.jsonl";

  std::vector<AIAssistantChat> results;
  parseKimiWire(wire, path, results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kKimiApplication);
  // Nothing in the journal names the session, so its path does.
  EXPECT_EQ(results[0].session_id, "7c1");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "add a retry");
  EXPECT_EQ(results[0].timestamp, 1777795163);

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "Wrapping the call.");
  EXPECT_EQ(results[1].timestamp, 1777795170);
}

TEST_F(AIAssistantChatsTest, test_kimi_session_id) {
  EXPECT_EQ(kimiSessionId("/home/user/.kimi-code/sessions/2026-05-03/7c1/"
                          "agents/main/wire.jsonl"),
            "7c1");
  // A subagent's journal belongs to the same session as the main one.
  EXPECT_EQ(kimiSessionId("/home/user/.kimi-code/sessions/2026-05-03/7c1/"
                          "agents/explore/wire.jsonl"),
            "7c1");
  // Anything not laid out that way names no session.
  EXPECT_EQ(kimiSessionId("/home/user/.kimi-code/sessions/7c1/wire.jsonl"), "");
  EXPECT_EQ(kimiSessionId("/home/user/a.jsonl"), "");
}

TEST_F(AIAssistantChatsTest, test_gemini_logs) {
  const std::string logs =
      R"([{"sessionId":"a","messageId":0,"timestamp":"2026-05-03T07:59:23Z","type":"user","message":"how do I list processes"},)"
      R"({"sessionId":"a","messageId":1,"type":"user","message":"/help"},)"
      R"({"sessionId":"a","messageId":2,"type":"user","message":""},)"
      R"({"sessionId":"a","messageId":3,"type":"info","message":"a notice"},)"
      R"({"sessionId":"b","messageId":0,"type":"user","message":"and now?"}])";

  std::vector<AIAssistantChat> results;
  parseGeminiLogs(logs, "/home/user/.gemini/tmp/9b2f/logs.json", results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kGeminiApplication);
  // The entry names the session it belongs to, which is what makes it
  // the same prompt the journal recorded rather than a second one.
  EXPECT_EQ(results[0].session_id, "a");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "how do I list processes");
  EXPECT_EQ(results[0].timestamp, 1777795163);

  EXPECT_EQ(results[1].session_id, "b");
  EXPECT_EQ(results[1].message, "and now?");
}

TEST_F(AIAssistantChatsTest, test_gemini_logs_without_session) {
  // An entry that names no session falls back to the project directory.
  const std::string logs = R"([{"type":"user","message":"hello"}])";

  std::vector<AIAssistantChat> results;
  parseGeminiLogs(logs, "/home/user/.gemini/tmp/9b2f/logs.json", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "9b2f");
  EXPECT_EQ(results[0].timestamp, 0);
}

TEST_F(AIAssistantChatsTest, test_gemini_checkpoint_file) {
  const std::string checkpoint =
      R"({"history":[)"
      R"({"role":"user","parts":[{"text":"summarize the diff"}]},)"
      R"({"role":"model","parts":[{"text":"It "},{"text":"renames the flag."}]},)"
      R"({"role":"model","parts":[{"functionCall":{"name":"read_file","args":{}}}]},)"
      R"({"role":"user","parts":[{"functionResponse":{"name":"read_file"}}]}]})";

  std::vector<AIAssistantChat> results;
  parseGeminiCheckpoint(
      checkpoint,
      "/home/user/.gemini/tmp/9b2f/checkpoint-review.json",
      results);

  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ(results[0].application, kGeminiApplication);
  EXPECT_EQ(results[0].session_id, "9b2f/checkpoint-review");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "summarize the diff");

  EXPECT_EQ(results[1].role, "assistant");
  EXPECT_EQ(results[1].message, "It renames the flag.");
  // A checkpoint records the conversation, not when it happened.
  EXPECT_EQ(results[1].timestamp, 0);
}

TEST_F(AIAssistantChatsTest, test_gemini_checkpoint_file_legacy) {
  // Older releases saved the bare array of turns.
  const std::string checkpoint =
      R"([{"role":"user","parts":[{"text":"and this one"}]}])";

  std::vector<AIAssistantChat> results;
  parseGeminiCheckpoint(
      checkpoint, "/home/user/.gemini/tmp/9b2f/checkpoint-old.json", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "9b2f/checkpoint-old");
  EXPECT_EQ(results[0].role, "user");
  EXPECT_EQ(results[0].message, "and this one");
}

TEST_F(AIAssistantChatsTest, test_gemini_checkpoint_file_beside_sessions) {
  // A checkpoint saved beside the sessions is one directory further
  // down, and that directory is named the same in every project, so it
  // is the one above that names the project.
  const std::string checkpoint =
      R"({"history":[{"role":"user","parts":[{"text":"summarize the diff"}]}]})";

  std::vector<AIAssistantChat> results;
  parseGeminiCheckpoint(
      checkpoint,
      "/home/user/.gemini/tmp/9b2f/chats/checkpoint-review.json",
      results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "9b2f/checkpoint-review");
}

TEST_F(AIAssistantChatsTest, test_gemini_file_malformed) {
  std::vector<AIAssistantChat> results;

  parseGeminiLogs("not json", "/home/user/logs.json", results);
  parseGeminiLogs(R"({"type":"user"})", "/home/user/logs.json", results);
  parseGeminiCheckpoint("not json", "/home/user/checkpoint-a.json", results);
  parseGeminiCheckpoint(R"({"history":"none"})",
                        "/home/user/checkpoint-a.json",
                        results);
  parseGeminiCheckpoint("42", "/home/user/checkpoint-a.json", results);

  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
