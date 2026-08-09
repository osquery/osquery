/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/ai_assistant_chats/antigravity.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>

namespace osquery {
namespace tables {

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

class AntigravityChatsTest : public ::testing::Test {};

TEST_F(AntigravityChatsTest, test_decode_hex_blob) {
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

TEST_F(AntigravityChatsTest, test_antigravity_conversation) {
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

TEST_F(AntigravityChatsTest, test_antigravity_step_skipped) {
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

} // namespace tables
} // namespace osquery
