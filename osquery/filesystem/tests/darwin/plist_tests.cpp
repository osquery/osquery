/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/config/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/base64.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

char* argv0;

namespace osquery {

class PlistTests : public testing::Test {};

TEST_F(PlistTests, test_parse_plist_content) {
  // Isolate plist parsing errors to the plist parser, instead of file reader.
  std::string content;
  readFile(getTestConfigDirectory() / "test.plist", content);

  pt::ptree tree;
  auto s = parsePlistContent(content, tree);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  // Check the specifics of the PLIST.
  EXPECT_EQ(tree.get<bool>("Disabled"), true);
  EXPECT_THROW(tree.get<bool>("foobar"), pt::ptree_bad_path);
  EXPECT_EQ(tree.get<std::string>("Label"), "com.apple.FileSyncAgent.sshd");

  std::vector<std::string> program_arguments = {
      "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
      "FileSyncAgent_sshd-keygen-wrapper",
      "-i",
      "-f",
      "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
      "FileSyncAgent_sshd_config",
  };
  pt::ptree program_arguments_tree = tree.get_child("ProgramArguments");
  std::vector<std::string> program_arguments_parsed;
  for (const auto& argument : program_arguments_tree) {
    program_arguments_parsed.push_back(argument.second.get<std::string>(""));
  }
  EXPECT_EQ(program_arguments_parsed, program_arguments);
}

TEST_F(PlistTests, test_parse_plist_from_file) {
  // Now read the plist from a file and parse.
  boost::property_tree::ptree tree;
  auto s = parsePlist(getTestConfigDirectory() / "test.plist", tree);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  // The tree has a key with ".", the plist level delimiter.
  EXPECT_EQ(tree.size(), 8U);
  EXPECT_EQ(tree.count("com"), 0U);

  // Make sure "." iteration still works.
  EXPECT_EQ(tree.get("inetdCompatibility.Wait", ""), "0");
}

TEST_F(PlistTests, test_parse_plist_array) {
  // Now read the plist from a file and parse.
  boost::property_tree::ptree tree;
  auto s = parsePlist(getTestConfigDirectory() / "test_array.plist", tree);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(PlistTests, test_parse_plist_content_with_blobs) {
  pt::ptree tree;
  fs::path test_root(getTestConfigDirectory());

  auto s = parsePlist((test_root / "test_binary.plist").string(), tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_THROW(tree.get<bool>("foobar"), pt::ptree_bad_path);
  EXPECT_EQ(tree.get<std::string>("SessionItems.Controller"),
            "CustomListItems");
  auto first_element =
      tree.get_child("SessionItems.CustomListItems").begin()->second;
  EXPECT_EQ(first_element.get<std::string>("Name"), "Flux");
  std::string alias = base64::decode(first_element.get<std::string>("Alias"));

  // Verify we parsed the binary blob correctly
  EXPECT_NE(alias.find("Applications/Flux.app"), std::string::npos);
}

TEST_F(PlistTests, test_parse_plist_content_with_non_utf8_key) {
  // Binary plist of {"\uD800": "x", "Label": "ok"}. The first key is an
  // unpaired UTF-16 surrogate, which has no UTF-8 form.
  const unsigned char content[] = {
      0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd2, 0x01, 0x02,
      0x03, 0x04, 0x61, 0xd8, 0x00, 0x55, 0x4c, 0x61, 0x62, 0x65, 0x6c,
      0x51, 0x78, 0x52, 0x6f, 0x6b, 0x08, 0x0d, 0x10, 0x16, 0x18, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b};

  pt::ptree tree;
  auto s = parsePlistContent(
      std::string(reinterpret_cast<const char*>(content), sizeof(content)),
      tree);
  EXPECT_TRUE(s.ok());

  // The key that cannot be represented is skipped, the rest is kept.
  EXPECT_EQ(tree.size(), 1U);
  EXPECT_EQ(tree.get<std::string>("Label"), "ok");
}
}
