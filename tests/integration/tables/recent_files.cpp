/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for windows_recent_files
// Spec file: specs/windows/windows_recent_files.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class RecentFilesTest : public testing::Test {
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

TEST_F(RecentFilesTest, test_sanity) {
  auto const data = execute_query("select * from recent_files");

  // Ideally we would check that there are some rows, but on CI there are none

  ValidationMap row_map = {
      {"uid", NonNegativeInt},
      {"filename", NormalType},
      {"path", NonEmptyString},
      {"mtime", NonNegativeInt},
      {"type", NonEmptyString},
      {"shortcut_path", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
