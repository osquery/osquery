/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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