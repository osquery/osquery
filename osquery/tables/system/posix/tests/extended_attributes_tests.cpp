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

// Include the 'xattr_utils.h' header file for macOS; it contains the
// compatibility wrappers for setxattr/getxattr/listxattr/removexattr
#ifdef __APPLE__
#include <TargetConditionals.h>

#ifdef TARGET_OS_MAC
#include "osquery/tables/system/darwin/xattr_utils.h"
#else
#error Unsupported macOS target
#endif
#endif

namespace osquery {
Status getAllExtendedAttributes(
    std::unordered_map<std::string, std::string>& attributes,
    const std::string& path);

class ExtendedAttributesTests : public testing::Test {};

TEST_F(ExtendedAttributesTests, test_extended_attributes) {
  std::string test_file_path = kTestDataPath + "test_xattrs.txt";
  std::vector<std::string> dummy_attributes = {
      "user.attribute01", "user.attribute02", "user.attribute03"};

  for (const auto& dummy_attr : dummy_attributes) {
    EXPECT_EQ(setxattr(test_file_path.c_str(),
                       dummy_attr.data(),
                       dummy_attr.data(),
                       dummy_attr.size(),
                       0),
              0);
  }

  std::unordered_map<std::string, std::string> attributes;
  auto status = getAllExtendedAttributes(attributes, test_file_path);

  EXPECT_TRUE(status.ok());
  if (!status.ok()) {
    std::cerr << status.getMessage() << "\n";
    return;
  }

  EXPECT_EQ(attributes.size(), dummy_attributes.size());

  for (const auto& p : attributes) {
    const auto& attribute_name = p.first;
    const auto& attribute_value = p.second;

    auto it = std::find(
        dummy_attributes.begin(), dummy_attributes.end(), attribute_name);
    EXPECT_TRUE(it != dummy_attributes.end());

    const auto& expected_value = *it;
    EXPECT_EQ(attribute_value, expected_value);
  }
}
} // namespace osquery
