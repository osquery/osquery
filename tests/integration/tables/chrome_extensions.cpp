/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for chrome_extensions
// Spec file: specs/chrome_extensions.table

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
  auto const data = execute_query("select * from chrome_extensions");
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"uid", IntType},
                           {"name", NonEmptyString},
                           {"identifier", NonEmptyString},
                           {"version", NonEmptyString},
                           {"description", NormalType},
                           {"locale", NormalType},
                           {"update_url", NonEmptyString},
                           {"author", NormalType},
                           {"persistent", IntType},
                           {"path", NonEmptyString},
                           {"permissions", NormalType},
                           {"profile", NonEmptyString}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
