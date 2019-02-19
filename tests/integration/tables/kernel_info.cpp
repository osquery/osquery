/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for kernel_info
// Spec file: specs/kernel_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class KernelInfo : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(KernelInfo, test_sanity) {
  QueryData data = execute_query("select * from kernel_info");
  ValidatatioMap row_map = {{"version", NonEmptyString},
                            {"arguments", NormalType},
                            {"path", NormalType},
                            {"device", NonEmptyString}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
