/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <string>
#include <vector>

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
namespace {

/**
 * @brief Encode a binary property list (bplist00) from encoded objects.
 *
 * The last object is the top-level one. Offsets and object references are
 * one byte each, so the objects must fit in the first 256 bytes.
 */
std::string binaryPlist(const std::vector<std::string>& objects) {
  std::string plist = "bplist00";
  std::string offsets;
  for (const auto& object : objects) {
    offsets.push_back(static_cast<char>(plist.size()));
    plist += object;
  }
  uint64_t offset_table = plist.size();
  plist += offsets;

  // The trailer: 5 unused bytes, the sort version, the size of an offset and
  // of an object reference, then the number of objects, the top-level object
  // and the offset of the offset table, as big-endian 64-bit integers.
  plist += std::string{0, 0, 0, 0, 0, 0, 1, 1};
  uint64_t count = objects.size();
  for (uint64_t field : {count, count - 1, offset_table}) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      plist.push_back(static_cast<char>((field >> shift) & 0xff));
    }
  }
  return plist;
}

/// Nest a string in arrays, each holding the previous object twice if shared.
std::string nestedArraysPlist(size_t levels, bool shared) {
  std::vector<std::string> objects = {"\x51x"};
  for (size_t i = 0; i < levels; ++i) {
    auto previous = static_cast<char>(objects.size() - 1);
    objects.push_back(shared ? std::string{'\xa2', previous, previous}
                             : std::string{'\xa1', previous});
  }
  return binaryPlist(objects);
}

} // namespace

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

TEST_F(PlistTests, test_parse_plist_content_malformed) {
  // An OpenStep dictionary left open, which no plist format accepts.
  pt::ptree tree;
  auto s = parsePlistContent("{", tree);
  EXPECT_FALSE(s.ok());
  EXPECT_FALSE(s.getMessage().empty());
}

TEST_F(PlistTests, test_parse_plist_content_key_without_utf8) {
  // A dictionary of two keys sharing one value: "k", and a lone UTF-16
  // surrogate (U+D800), which has no UTF-8 form.
  auto content = binaryPlist({
      std::string{'\x61', '\xd8', '\x00'},
      "\x51k",
      "\x51v",
      std::string{'\xd2', 0, 1, 2, 2},
  });

  pt::ptree tree;
  auto s = parsePlistContent(content, tree);
  EXPECT_TRUE(s.ok()) << s.getMessage();
  EXPECT_EQ(tree.size(), 1U);
  EXPECT_EQ(tree.get<std::string>("k", ""), "v");
}

TEST_F(PlistTests, test_parse_plist_content_nesting_limit) {
  pt::ptree tree;
  auto s = parsePlistContent(nestedArraysPlist(64, false), tree);
  EXPECT_TRUE(s.ok()) << s.getMessage();

  s = parsePlistContent(nestedArraysPlist(65, false), tree);
  EXPECT_FALSE(s.ok());
  EXPECT_TRUE(tree.empty());
}

TEST_F(PlistTests, test_parse_plist_content_shared_containers) {
  // A binary plist may reference one array from many places.
  pt::ptree tree;
  auto s = parsePlistContent(nestedArraysPlist(2, true), tree);
  EXPECT_TRUE(s.ok()) << s.getMessage();
  EXPECT_EQ(tree.get_child("root").size(), 2U);

  // 20 levels of such arrays expand 123 bytes into about 2^21 values.
  s = parsePlistContent(nestedArraysPlist(20, true), tree);
  EXPECT_FALSE(s.ok());
  EXPECT_TRUE(tree.empty());
}
}
