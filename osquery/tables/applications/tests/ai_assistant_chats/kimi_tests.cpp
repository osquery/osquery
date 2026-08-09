/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/kimi.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class KimiChatsTest : public ::testing::Test {};

TEST_F(KimiChatsTest, test_kimi_wire) {
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

TEST_F(KimiChatsTest, test_kimi_session_id) {
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

} // namespace tables
} // namespace osquery
