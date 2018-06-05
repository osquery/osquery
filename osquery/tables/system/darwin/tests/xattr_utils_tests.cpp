/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <sys/xattr.h>

#include <boost/filesystem.hpp>

#include "osquery/tests/test_util.h"
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {
Status readSpecialExtendedAttribute(
    std::vector<std::pair<std::string, std::string>>& output,
    const std::string& path,
    const std::string& name);

namespace tables {
const std::string kQuarantineXattr = "com.apple.quarantine";
const std::uint8_t kQuarantineXattrValue[] = {
    0x30, 0x30, 0x30, 0x31, 0x3B, 0x35, 0x35, 0x34, 0x39, 0x34, 0x64, 0x65,
    0x33, 0x3B, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x5C, 0x78, 0x32, 0x30,
    0x43, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x3B, 0x36, 0x41, 0x30, 0x45, 0x43,
    0x39, 0x32, 0x44, 0x2D, 0x31, 0x38, 0x38, 0x32, 0x2D, 0x34, 0x33, 0x35,
    0x38, 0x2D, 0x41, 0x33, 0x31, 0x35, 0x2D, 0x35, 0x38, 0x36, 0x42, 0x41,
    0x36, 0x35, 0x46, 0x38, 0x46, 0x37, 0x37};

class MacOSExtendedAttrTests : public testing::Test {};

TEST_F(MacOSExtendedAttrTests, test_invalid_special_xattr) {
  auto test_file_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  {
    std::fstream test_file(test_file_path, std::ios::out);
    EXPECT_EQ(!test_file, false);
  }

  const char dummy_string[] = "test";
  EXPECT_EQ(setxattr(test_file_path.c_str(),
                     dummy_string,
                     dummy_string,
                     sizeof(dummy_string),
                     0,
                     XATTR_NOFOLLOW),
            0);

  // The function should not attempt to expand this attribute
  std::vector<std::pair<std::string, std::string>> expanded_attributes;
  auto status = readSpecialExtendedAttribute(
      expanded_attributes, test_file_path, dummy_string);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(expanded_attributes.size(), 0U);

  fs::remove(test_file_path);
}

TEST_F(MacOSExtendedAttrTests, test_quarantine_xattrs) {
  auto test_file_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  {
    std::fstream test_file(test_file_path, std::ios::out);
    EXPECT_EQ(!test_file, false);
  }

  EXPECT_EQ(setxattr(test_file_path.c_str(),
                     kQuarantineXattr.c_str(),
                     kQuarantineXattrValue,
                     sizeof(kQuarantineXattrValue),
                     0,
                     XATTR_NOFOLLOW),
            0);

  std::vector<std::pair<std::string, std::string>> expanded_attributes;
  auto status = readSpecialExtendedAttribute(
      expanded_attributes, test_file_path, kQuarantineXattr);
  EXPECT_TRUE(status.ok());

  const std::map<std::string, std::string> expected = {
      {"quarantine_agent", "Google Chrome"},
      {"quarantine_event_id", "6A0EC92D-1882-4358-A315-586BA65F8F77"},
      {"quarantine_timestamp", "1430867427"}};

  size_t matching_entries = 0U;

  for (const auto& p : expanded_attributes) {
    const auto& name = p.first;
    const auto& value = p.second;

    auto it = expected.find(name);
    if (it == expected.end()) {
      continue;
    }

    if (it->second != value) {
      continue;
    }

    matching_entries++;
  }

  EXPECT_EQ(matching_entries, expected.size());

  fs::remove(test_file_path);
}
} // namespace tables
} // namespace osquery
