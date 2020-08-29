/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for sandboxes
// Spec file: specs/darwin/sandboxes.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/logger/logger.h>

namespace osquery {
namespace table_tests {

class Sandboxes : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(Sandboxes, test_sanity) {
  QueryData data = execute_query("select * from sandboxes");

  if (!data.empty()) {
    ValidationMap row_map = {
        {"label", NonEmptyString},
        {"user", NonEmptyString},
        {"enabled", Bool},
        {"build_id", NonEmptyString},
        {"bundle_path", NormalType},
        {"path", DirectoryOnDisk},
    };
    validate_rows(data, row_map);
  } else {
    LOG(WARNING)
        << "sandboxes table returned no results and therefore won't be tested";
  }
}

} // namespace table_tests
} // namespace osquery
