/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/posix/xattrs.h>
#include <osquery/utils/scope_guard.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <sys/xattr.h>

#if defined(__APPLE__)
#define EXTENDED_ATTRIBUTE_PREFIX ""

#define setxattr(path, name, value, size, flags)                               \
  ::setxattr(path, name, value, size, 0, flags)

#else
#define EXTENDED_ATTRIBUTE_PREFIX "user."
#endif

namespace osquery {
namespace {
const std::unordered_map<std::string, ExtendedAttributeValue>
    kTestAttributeList = {
        {EXTENDED_ATTRIBUTE_PREFIX "testValue1", {0x01, 0x01, 0x01, 0x01}},
        {EXTENDED_ATTRIBUTE_PREFIX "testValue2", {0x02, 0x02, 0x02, 0x02}}};
}

class XattrTests : public testing::Test {
  void SetUp() override {
    test_file_path = boost::filesystem::temp_directory_path() /
                     boost::filesystem::unique_path("osquery.tests.%%%%.%%%%");

    writeTextFile(test_file_path.string(), "test");

    for (const auto& p : kTestAttributeList) {
      const auto& attribute_name = p.first;
      const auto& attribute_value = p.second;

      auto path = test_file_path.string();
      if (setxattr(path.c_str(),
                   attribute_name.c_str(),
                   attribute_value.data(),
                   attribute_value.size(),
                   XATTR_CREATE) != 0) {
        throw std::runtime_error(
            "Failed to set the extended attributes on the test file. errno "
            "value: " +
            std::to_string(errno));
      }
    }
  }

  void TearDown() override {
    boost::filesystem::remove(test_file_path);
  }

 public:
  boost::filesystem::path test_file_path;
};

TEST_F(XattrTests, getExtendedAttributesNames) {
  int fd = open(test_file_path.c_str(), O_RDONLY);

  ASSERT_GE(fd, 0);

  auto fd_scope = scope_guard::create([&] { close(fd); });

  auto list_result = getExtendedAttributesNames(fd);

  ASSERT_TRUE(list_result.isValue())
      << "Error code: "
      << static_cast<int>(list_result.getError().getErrorCode());
  const auto& attribute_name_list = list_result.get();
  ASSERT_GE(attribute_name_list.size(), kTestAttributeList.size());

  for (const auto& attribute_name : kTestAttributeList) {
    EXPECT_TRUE(std::find(attribute_name_list.begin(),
                          attribute_name_list.end(),
                          attribute_name.first) != attribute_name_list.end());
  }
}

TEST_F(XattrTests, getExtendedAttributeValue) {
  int fd = open(test_file_path.c_str(), O_RDONLY);

  ASSERT_GE(fd, 0);

  auto fd_scope = scope_guard::create([&] { close(fd); });

  for (const auto& p : kTestAttributeList) {
    const auto& attribute_name = p.first;
    const auto& expected_attribute_value = p.second;

    auto value_result = getExtendedAttributeValue(fd, attribute_name);

    ASSERT_TRUE(value_result.isValue())
        << "Error code: "
        << static_cast<int>(value_result.getError().getErrorCode());

    const auto& actual_attribute_value = value_result.get();

    EXPECT_EQ(actual_attribute_value, expected_attribute_value);
  }
}

TEST_F(XattrTests, getExtendedAttributes) {
  auto xattr_map_result = getExtendedAttributes(test_file_path.string());

  ASSERT_TRUE(xattr_map_result.isValue());

  const auto& xattr_map = xattr_map_result.get();

  for (const auto& p : kTestAttributeList) {
    const auto& attribute_name = p.first;
    const auto& expected_attribute_value = p.second;

    auto it = xattr_map.find(attribute_name);
    ASSERT_TRUE(it != xattr_map.end());

    const auto& actual_attribute_value = it->second;
    EXPECT_EQ(actual_attribute_value, expected_attribute_value);
  }
}
} // namespace osquery
