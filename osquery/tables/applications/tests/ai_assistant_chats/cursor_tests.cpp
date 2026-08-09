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
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

class CursorChatsTest : public ::testing::Test {};

TEST_F(CursorChatsTest, test_cursor_bubble) {
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

TEST_F(CursorChatsTest, test_cursor_bubble_skipped) {
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

} // namespace tables
} // namespace osquery
