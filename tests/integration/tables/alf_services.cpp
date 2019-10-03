/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for alf_services
// Spec file: specs/darwin/alf_services.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class alfServices : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(alfServices, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from alf_services");
  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"screen_sharing", IntType},
      {"file_sharing", IntType},
      {"printer_sharing", IntType},
      {"remote_login", IntType},
      {"remote_management", IntType},
      {"remote_apple_events", IntType},
      {"internet_sharing", IntType},
      {"bluetooth_sharing", IntType},
      {"disc_sharing", IntType},
      {"content_caching", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
