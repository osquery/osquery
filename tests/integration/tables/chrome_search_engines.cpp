/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for chrome_search_engines
// Spec file: specs/chrome_search_engines.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class chromeSearchEngines : public testing::Test {
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

TEST_F(chromeSearchEngines, test_sanity) {
  auto const data = execute_query("select * from chrome_search_engines");

  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {{"browser_type", NonEmptyString},
                           {"uid", IntType},
                           {"profile", NonEmptyString},
                           {"profile_path", FileOnDisk},
                           {"name", NonEmptyString},
                           {"keyword", NonEmptyString},
                           {"url", NonEmptyString}};
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
