/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for sandboxes
// Spec file: specs/darwin/sandboxes.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/logger.h>

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
    ValidatatioMap row_map = {
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
