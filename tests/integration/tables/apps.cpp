/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for apps
// Spec file: specs/darwin/apps.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace table_tests {

class AppsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(AppsTest, test_sanity) {
  auto const data = execute_query("select * from apps");

  auto verify_zero_one_or_empty = [](std::string const& value) {
    if (value.empty()) {
      return true;
    }
    auto cast_result = tryTo<int64_t>(value);
    if (!cast_result) {
      return false;
    }
    return ((cast_result.get() == 0) || (cast_result.get() == 1));
  };

  ASSERT_GE(data.size(), 1ul);
  ValidationMap row_map = {
      {"name", NonEmptyString},
      {"path", DirectoryOnDisk},
      {"bundle_executable", NormalType},
      {"bundle_identifier", NormalType},
      {"bundle_name", NormalType},
      {"bundle_short_version", NormalType},
      {"bundle_version", NormalType},
      {"bundle_package_type", NormalType},
      {"environment", NormalType},
      {"element", verify_zero_one_or_empty},
      {"compiler", NormalType},
      {"development_region", NormalType},
      {"display_name", NormalType},
      {"info_string", NormalType},
      {"minimum_system_version", NormalType},
      {"category", NormalType},
      {"applescript_enabled", verify_zero_one_or_empty},
      {"copyright", NormalType},
      {"last_opened_time", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
