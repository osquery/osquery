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

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/tables/system/posix/extended_attributes.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {
Status getAllExtendedAttributes(ExtendedAttributeList& attributes,
                                const std::string& path);

class ExtendedAttributesTests : public testing::Test {};

TEST_F(ExtendedAttributesTests, test_extended_attributes) {
  auto test_file_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  {
    std::fstream test_file(test_file_path, std::ios::out);
    EXPECT_EQ(!test_file, false);
  }

  std::vector<std::string> dummy_attrs = {
      "user.attribute01", "user.attribute02", "user.attribute03"};

  for (const auto& dummy_attr : dummy_attrs) {
    EXPECT_EQ(setxattr(test_file_path.c_str(),
                       dummy_attr.data(),
                       dummy_attr.data(),
                       dummy_attr.size(),
                       0),
              0);
  }

  ExtendedAttributeList attributes;
  auto status = getAllExtendedAttributes(attributes, test_file_path);

  EXPECT_TRUE(status.ok());
  if (!status.ok()) {
    std::cerr << status.getMessage() << "\n";
    return;
  }

  size_t matching_entries = 0U;

  for (const auto& p : attributes) {
    const auto& attribute_name = p.first;
    const auto& attribute_value = p.second;

    auto it = std::find(dummy_attrs.begin(), dummy_attrs.end(), attribute_name);
    if (it == dummy_attrs.end()) {
      continue;
    }

    const auto& expected_value = *it;
    if (attribute_value != expected_value) {
      continue;
    }

    matching_entries++;
  }

  EXPECT_EQ(matching_entries, dummy_attrs.size());

  fs::remove(test_file_path);
}
} // namespace osquery
