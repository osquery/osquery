/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for known_hosts
// Spec file: specs/posix/known_hosts.table

#include <osquery/logger/logger.h>
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
    auto const row_map = ValidationMap{
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
