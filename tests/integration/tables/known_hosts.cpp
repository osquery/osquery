
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for known_hosts
// Spec file: specs/posix/known_hosts.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
namespace {

class KnownHostsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(KnownHostsTest, test_sanity) {
  QueryData const rows = execute_query("select * from known_hosts");
  if (rows.empty()) {
    LOG(WARNING) << "select from \"known_hosts\" table returned no results and "
                    "therefore won't be tested";
  } else {
    auto const row_map = ValidatatioMap{
        {"uid", IntType},
        {"key", NonEmptyString},
        {"key_file", FileOnDisk},
    };
    validate_rows(rows, row_map);
  }
}

} // namespace
} // namespace table_tests
} // namespace osquery
