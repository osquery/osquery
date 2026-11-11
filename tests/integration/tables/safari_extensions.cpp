/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for safari_extensions
// Spec file: specs/darwin/safari_extensions.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class safariExtensions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(safariExtensions, test_sanity) {
  // Query requires a users JOIN (or uid constraint) and Full Disk Access to
  // read Safari container plists. Discovery covers:
  //   - /Applications/*/Contents/PlugIns/*.appex
  //   - recursive depth-limited walk of ~/Library/Application Support for
  //     *.app/Contents/PlugIns/*.appex (e.g. Webex; see osquery#8684 /
  //     Fleet#6950)
  // Rows are emitted only when the bundle id appears in the user's
  // AppExtensions or WebExtensions Extensions.plist.
  auto const data = execute_query(
      "select safari_extensions.* from users "
      "cross join safari_extensions using (uid)");
  ValidationMap row_map = {
      {"uid", IntType},
      {"name", NormalType},
      {"identifier", NormalType},
      {"version", NormalType},
      {"sdk", NormalType},
      {"description", NormalType},
      {"path", NormalType},
      {"bundle_version", NormalType},
      {"copyright", NormalType},
  };
  if (!data.empty()) {
    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
