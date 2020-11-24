/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/posix/xattrs.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <sys/capability.h>
#include <sys/xattr.h>

namespace osquery {
namespace {
struct ExtendedAttributeTestValue final {
  ExtendedAttributeValue input;
  std::string expected_output;
  bool base64{false};
};

const std::string kCapabilitiesAttributeName{"security.capability"};
const std::string kInputCapabilities{
    "cap_dac_override,cap_net_admin,cap_net_raw+eip"};
const std::string kExpectedCapabilities{"= " + kInputCapabilities};

// clang-format off
const std::unordered_map<std::string, ExtendedAttributeTestValue> kTestAttributeList = {
  // Not printable
  {
    "user.base64Value1",
    {
      { 0x01, 0x01, 0x01, 0x01 },
      "AQEBAQ==",
      true
    }
  },

  // This qualifies as printable, since it is terminated with a 0
  {
    "user.printableValue2",
    {
      { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x6f, 0x73, 0x71, 0x75, 0x65, 0x72, 0x79, 0x21, 0x00 },
      "Hello, osquery!",
      false
    }
  }
};
// clang-format on
} // namespace

namespace tables {
extern Status generateXattrRowsForPath(QueryData& output,
                                       const std::string& path);
}

class ExtendedAttributesTableTests : public testing::Test {
  void SetUp() override {
    // Create a new test file
    temporary_file_path =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("osquery.tests.%%%%.%%%%");

    writeTextFile(temporary_file_path.string(), "test");

    // Set the user extended attributes
    const auto& path = temporary_file_path.string();

    for (const auto& p : kTestAttributeList) {
      const auto& attribute_name = p.first;
      if (attribute_name.find("user.") != 0U) {
        throw std::logic_error("Invalud test attribute name");
      }

      const auto& desc = p.second;
      const auto& input_value = desc.input;

      if (setxattr(path.c_str(),
                   attribute_name.c_str(),
                   input_value.data(),
                   input_value.size(),
                   XATTR_CREATE) != 0) {
        throw std::runtime_error(
            "Failed to set the extended attributes on the test file");
      }
    }

    // Set the capabilities
    auto capabilities = cap_from_text(kInputCapabilities.c_str());
    if (cap_set_file(path.c_str(), capabilities) == 0) {
      check_capabilities = true;
    } else {
      std::cerr << "cap_set_file() failed with errno " << errno
                << ". Skipping tests on capabilities\n";
    }
  }

  void TearDown() override {
    boost::filesystem::remove(temporary_file_path);
  }

 public:
  boost::filesystem::path temporary_file_path;
  bool check_capabilities{false};
};

TEST_F(ExtendedAttributesTableTests, generate) {
  QueryData output;
  auto status =
      tables::generateXattrRowsForPath(output, temporary_file_path.string());
  ASSERT_TRUE(status.ok());

  // Make sure we have the correct number of rows; if we are not being run
  // as root, we may have failed to set the capabilities on the test file
  auto expected_row_count = kTestAttributeList.size();
  if (check_capabilities) {
    ++expected_row_count;
  }

  ASSERT_EQ(output.size(), expected_row_count);

  auto temp_folder = boost::filesystem::temp_directory_path();
  const auto& expected_directory_field = temp_folder.string();

  for (const auto& r : output) {
    ASSERT_EQ(r.size(), 5U);
    EXPECT_EQ(r.at("path"), temporary_file_path.string());
    EXPECT_EQ(r.at("directory"), expected_directory_field);

    const auto& key = r.at("key");
    if (key == kCapabilitiesAttributeName) {
      EXPECT_EQ(r.at("base64"), "0");
      EXPECT_EQ(r.at("value"), kExpectedCapabilities);

    } else {
      auto it = kTestAttributeList.find(key);
      ASSERT_TRUE(it != kTestAttributeList.end());

      const auto& expected_values = it->second;
      EXPECT_EQ(r.at("base64"), expected_values.base64 ? "1" : "0");
      EXPECT_EQ(r.at("value"), expected_values.expected_output);
    }
  }
}
} // namespace osquery
