/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for chrome_extensions
// Spec file: specs/chrome_extensions.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class chromeExtensions : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, false);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, false);
    Dispatcher::instance().resetStopping();
  }
#endif
};

TEST_F(chromeExtensions, test_sanity) {
  auto const data = execute_query(
      "select *, permissions_json, optional_permissions_json, manifest_json "
      "from chrome_extensions");

  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"browser_type", NormalType},
                           {"uid", IntType},
                           {"name", NormalType},
                           {"profile", NormalType},
                           {"profile_path", NormalType},
                           {"identifier", NormalType},
                           {"referenced_identifier", NormalType},
                           {"version", NormalType},
                           {"description", NormalType},
                           {"default_locale", NormalType},
                           {"current_locale", NormalType},
                           {"update_url", NormalType},
                           {"author", NormalType},
                           {"persistent", IntType},
                           {"path", NormalType},
                           {"permissions", NormalType},
                           {"permissions_json", NormalType},
                           {"optional_permissions", NormalType},
                           {"optional_permissions_json", NormalType},
                           {"manifest_hash", NormalType},
                           {"referenced", IntType},
                           {"from_webstore", NormalType},
                           {"state", NormalType},
                           {"install_time", NormalType},
                           {"install_timestamp", IntType},
                           {"manifest_json", NormalType}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
