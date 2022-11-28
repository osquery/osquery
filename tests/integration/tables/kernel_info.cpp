/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
  ValidationMap row_map = {{"version", NonEmptyString},
                           {"arguments", NormalType},
                           {"path", NormalType},
                           {"device", NormalType}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
