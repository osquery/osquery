/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

namespace osquery::table_tests {

class Secureboot : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(Secureboot, test_sanity) {
  bool secureboot_supported{false};

  {
    auto platform_info_rows =
        execute_query("SELECT firmware_type FROM platform_info;");

    ASSERT_EQ(platform_info_rows.size(), 1);

    const auto& platform_info = platform_info_rows[0];
    ASSERT_EQ(platform_info.count("firmware_type"), 1);

    secureboot_supported = platform_info.at("firmware_type") == "uefi";
  }

  auto secureboot_data = execute_query("SELECT * FROM secureboot;");
  if (!secureboot_supported) {
    ASSERT_TRUE(secureboot_data.empty());
    return;
  }

  ASSERT_EQ(secureboot_data.size(), 1);
  static const ValidationMap kValidationMap{
      {"secure_boot", IntOrEmpty},
      {"setup_mode", IntOrEmpty},
  };

  validate_rows(secureboot_data, kValidationMap);
}

} // namespace osquery::table_tests
