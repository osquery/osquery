/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/tables/applications/ai_assistant_chats/vscode.h>

namespace osquery {
namespace tables {

class VSCodeChatsTest : public ::testing::Test {};

TEST_F(VSCodeChatsTest, test_copilot_chat_session) {
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

TEST_F(VSCodeChatsTest, test_copilot_chat_session_fallbacks) {
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

TEST_F(VSCodeChatsTest, test_chat_session_nested_response_parts) {
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

TEST_F(VSCodeChatsTest, test_chat_session_journal) {
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

TEST_F(VSCodeChatsTest, test_chat_session_journal_without_snapshot) {
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

TEST_F(VSCodeChatsTest, test_chat_session_malformed) {
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
