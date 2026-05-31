/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/tables.h>
#include <osquery/tables/system/windows/shellbags.h>

#include <string>
#include <vector>

namespace osquery {
namespace tables {

class ParseShellDataTests : public testing::Test {};

namespace {

struct ParseResult {
  QueryData rows;
  std::vector<std::string> build_shellbag;
};

ParseResult run(const std::string& hex) {
  ParseResult out;
  parseShellData(hex, out.build_shellbag, out.rows, "S-1-5-21-TEST", "test");
  return out;
}

} // namespace

// sig=1F root folder GUID (same hex as ShellitemTests::test_shellitem_rootentry).
TEST_F(ParseShellDataTests, root_folder_dispatches_and_emits_guid) {
  auto r = run(
      "3A001F44471A0359723FA74489C55595FE6B30EE260001002600EFBE100000002A4B9884"
      "B387D50168891281D387D501BF5E6881D387D50114000000");
  ASSERT_EQ(r.rows.size(), 1u);
  // guidLookup may rewrite to a friendly name; on a clean test box it returns
  // the {GUID} unchanged. Match the GUID substring rather than the full form.
  EXPECT_NE(r.rows[0]["path"].find("59031A47-3F72-44A7-89C5-5595FE6B30EE"),
            std::string::npos);
}

// sig=2F drive letter (same hex as ShellitemTests::test_shellitem_driveletterentry).
TEST_F(ParseShellDataTests, drive_letter_dispatches_and_emits_path) {
  auto r = run("19002F433A5C000000000000000000000000000000000000000000");
  ASSERT_EQ(r.rows.size(), 1u);
  EXPECT_EQ(r.rows[0]["path"], "C:\\");
}

// sig=01 control panel category.
TEST_F(ParseShellDataTests, control_panel_category_dispatches) {
  auto r = run("0C0001008421DE39050000000000");
  ASSERT_EQ(r.rows.size(), 1u);
  EXPECT_EQ(r.rows[0]["path"], "System and Security");
}

// sig=71 control panel item.
TEST_F(ParseShellDataTests, control_panel_item_dispatches) {
  auto r = run("1E007180000000000000000000006ABE817B2BCE7646A29EEB907A5126C50000");
  ASSERT_EQ(r.rows.size(), 1u);
  EXPECT_NE(r.rows[0]["path"].find("7B81BE6A-CE2B-4676-A29E-EB907A5126C5"),
            std::string::npos);
}

// sig=C3 network share (same hex as ShellitemTests::test_shellitem_networkshare).
TEST_F(ParseShellDataTests, network_share_dispatches) {
  auto r = run(
      "3A00C301815C5C766D776172652D686F73745C53686172656420466F6C6465727300564D"
      "776172652053686172656420466F6C64657273003F000000");
  ASSERT_EQ(r.rows.size(), 1u);
  EXPECT_EQ(r.rows[0]["path"], "\\\\vmware-host\\Shared Folders");
}

// sig=00 + EEBBFE23 variable GUID.
TEST_F(ParseShellDataTests, variable_guid_dispatches) {
  auto r = run(
      "200000001A00EEBBFE23000010003ACCBFB42CDB4C42B0297FE99A87C64100000000");
  ASSERT_EQ(r.rows.size(), 1u);
  EXPECT_NE(r.rows[0]["path"].find("B4BFCC3A-DB2C-424C-B029-7FE99A87C641"),
            std::string::npos);
}

// GHSA-h348-cc3h-grw6: a 3-byte REG_BINARY value whose third byte is 0x1F
// would crash the old parser when rootFolderItem did substr(8, 32) on a
// 6-character hex string. Now passes — bounds-checked reader returns a
// sentinel, no exception thrown.
TEST_F(ParseShellDataTests, ghsa_h348_3byte_sig1F_does_not_crash) {
  // sig_byte read succeeds (0x1F), routes to root-folder branch,
  // rootFolderItem returns "[UNKNOWN ROOT FOLDER]", guidLookup wraps it.
  // The exact path string isn't load-bearing — the security guarantee
  // is "no uncaught exception."
  EXPECT_NO_THROW({
    auto r = run("00001F");
    EXPECT_EQ(r.rows.size(), 1u);
  });
}

TEST_F(ParseShellDataTests, DISABLED_ghsa_h348_empty_input_does_not_crash) {
  EXPECT_NO_THROW({
    auto r = run("");
    ASSERT_EQ(r.rows.size(), 1u);
  });
}

TEST_F(ParseShellDataTests, DISABLED_ghsa_h348_short_drive_letter_does_not_crash) {
  // sig=2F drive letter, byte at hex 6 = 0x80 → enters the GUID
  // sub-branch. parseShellData reads substr(8, 32) (returns empty on
  // this short input), then guidParse internally does substr(8, 4) on
  // that empty string and throws on master.
  EXPECT_NO_THROW({
    auto r = run("00002F80");
    ASSERT_EQ(r.rows.size(), 1u);
  });
}

TEST_F(ParseShellDataTests, ghsa_h348_short_control_panel_does_not_crash) {
  // sig=01, but no panel_id byte present.
  EXPECT_NO_THROW({
    auto r = run("000001");
    ASSERT_EQ(r.rows.size(), 1u);
  });
}

} // namespace tables
} // namespace osquery
