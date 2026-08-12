/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/gemini.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class GeminiChatsTest : public ::testing::Test {};

TEST_F(GeminiChatsTest, test_gemini_session) {
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

TEST_F(GeminiChatsTest, test_gemini_session_skipped) {
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

TEST_F(GeminiChatsTest, test_gemini_session_checkpoint) {
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

TEST_F(GeminiChatsTest, test_gemini_session_revises_by_id) {
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

TEST_F(GeminiChatsTest, test_gemini_logs) {
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

TEST_F(GeminiChatsTest, test_gemini_logs_without_session) {
  // An entry that names no session falls back to the project directory.
  const std::string logs = R"([{"type":"user","message":"hello"}])";

  std::vector<AIAssistantChat> results;
  parseGeminiLogs(logs, "/home/user/.gemini/tmp/9b2f/logs.json", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].session_id, "9b2f");
  EXPECT_EQ(results[0].timestamp, 0);
}

TEST_F(GeminiChatsTest, test_gemini_checkpoint_file) {
  const std::string checkpoint =
      R"({"history":[)"
      R"({"role":"user","parts":[{"text":"summarize the diff"}]},)"
      R"({"role":"model","parts":[{"text":"It "},{"text":"renames the flag."}]},)"
      R"({"role":"model","parts":[{"functionCall":{"name":"read_file","args":{}}}]},)"
      R"({"role":"user","parts":[{"functionResponse":{"name":"read_file"}}]}]})";

  std::vector<AIAssistantChat> results;
  parseGeminiCheckpoint(checkpoint,
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

TEST_F(GeminiChatsTest, test_gemini_checkpoint_file_legacy) {
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

TEST_F(GeminiChatsTest, test_gemini_checkpoint_file_beside_sessions) {
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

TEST_F(GeminiChatsTest, test_gemini_file_malformed) {
  std::vector<AIAssistantChat> results;

  parseGeminiLogs("not json", "/home/user/logs.json", results);
  parseGeminiLogs(R"({"type":"user"})", "/home/user/logs.json", results);
  parseGeminiCheckpoint("not json", "/home/user/checkpoint-a.json", results);
  parseGeminiCheckpoint(
      R"({"history":"none"})", "/home/user/checkpoint-a.json", results);
  parseGeminiCheckpoint("42", "/home/user/checkpoint-a.json", results);

  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
