/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/tests/test_util.h"
#include "osquery/tables/system/posix/xattr_utils.h"

namespace fs = boost::filesystem;

#ifdef __linux__
#define WRITE_ATTRIBUTE_NAME_PREFIX "user."
#define READ_ATTRIBUTE_NAME_PREFIX "user."
#elif defined(__FreeBSD__)
#define WRITE_ATTRIBUTE_NAME_PREFIX ""
#define READ_ATTRIBUTE_NAME_PREFIX "user."
#else
#define WRITE_ATTRIBUTE_NAME_PREFIX ""
#define READ_ATTRIBUTE_NAME_PREFIX ""
#endif

namespace osquery {
class ExtendedAttributesTests : public testing::Test {};

TEST_F(ExtendedAttributesTests, test_extended_attributes) {
  auto test_file_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  {
    std::fstream test_file(test_file_path, std::ios::out);
    EXPECT_EQ(!test_file, false);
  }

  std::unordered_map<std::string, std::string> test_attributes = {
    {WRITE_ATTRIBUTE_NAME_PREFIX "attribute01", "value01"},
    {WRITE_ATTRIBUTE_NAME_PREFIX "attribute02", "value02"},
    {WRITE_ATTRIBUTE_NAME_PREFIX "attribute03", "value03"}
  };

  auto succeeded = setExtendedAttributes(test_file_path, test_attributes);
  EXPECT_TRUE(succeeded);
  if (!succeeded) {
    std::cerr << "Failed to set the extended attributes on the test file\n";
    return;
  }

  ExtendedAttributes attributes;
  succeeded = getExtendedAttributes(attributes, test_file_path);
  EXPECT_TRUE(succeeded);
  if (!succeeded) {
    std::cerr << "Failed to get the extended attributes from the test file\n";
    return;
  }

  std::unordered_map<std::string, std::string> expected_attributes = {
    {READ_ATTRIBUTE_NAME_PREFIX "attribute01", "value01"},
    {READ_ATTRIBUTE_NAME_PREFIX "attribute02", "value02"},
    {READ_ATTRIBUTE_NAME_PREFIX "attribute03", "value03"},
  };

  size_t matching_entries = 0U;
  for (const auto& p : attributes) {
    const auto &attribute_name = p.first;
    const auto& attribute_value = p.second;

    auto it = expected_attributes.find(attribute_name);
    if (it == expected_attributes.end()) {
      continue;
    }

    const auto& expected_value = it->second;
    if (attribute_value != expected_value) {
      continue;
    }

    matching_entries++;
  }

  EXPECT_EQ(matching_entries, test_attributes.size());

  fs::remove(test_file_path);
}
} // namespace osquery
