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

    if (isPlatform(PlatformType::TYPE_OSX)) {
#ifdef __aarch64__
      secureboot_supported = false;
#endif
    } else {
      secureboot_supported = platform_info.at("firmware_type") == "uefi";
    }
  }

  if (!secureboot_supported) {
    return;
  }

  auto secureboot_data = execute_query("SELECT * FROM secureboot;");

  // Values should only ever be integers or empty:
  ValidationMap row_map{
      {"secure_boot", IntOrEmpty},
  };

  // Windows and Linux have setup_mode, macOS has secure_mode:
  if (isPlatform(PlatformType::TYPE_WINDOWS) ||
      isPlatform(PlatformType::TYPE_LINUX)) {
    row_map.emplace("setup_mode", IntOrEmpty);
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("secure_mode", IntOrEmpty);
  }

  // Check that the above assumptions are true:
  validate_rows(secureboot_data, row_map);
}

} // namespace osquery::table_tests
