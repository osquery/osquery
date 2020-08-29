/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for chrome_extension_content_scripts
// Spec file: specs/chrome_extension_content_scripts.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class chromeExtensions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(chromeExtensions, test_sanity) {
  auto const data =
      execute_query("select * from chrome_extension_content_scripts");
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"uid", IntType},
                           {"identifier", NonEmptyString},
                           {"version", NonEmptyString},
                           {"script", NormalType},
                           {"match", NormalType}};
  validate_rows(data, row_map);
}
} // namespace table_tests
} // namespace osquery