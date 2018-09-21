
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for kernel_modules
// Spec file: specs/linux/kernel_modules.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class KernelModules : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(KernelModules, test_sanity) {
  QueryData data = execute_query("select * from kernel_modules");
  ASSERT_GT(data.size(), 0ul);
  ValidatatioMap row_map = {
      {"name", NonEmptyString},
      {"size", NonNegativeInt},
      {"used_by", NonEmptyString},
      {"status", NonEmptyString},
      {"address", NonNegativeInt},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
