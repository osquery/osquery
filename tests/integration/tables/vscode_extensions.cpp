/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for vscode_extensions
// Spec file: specs/vscode_extensions.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class vscodeExtensions : public testing::Test {
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

TEST_F(vscodeExtensions, test_sanity) {
  auto const data = execute_query("select * from vscode_extensions");
  if (data.empty()) {
    LOG(WARNING)
        << "Empty results of query from 'vscode_extensions', assume there "
           "is no vscode on the system";
    return;
  }

  ValidationMap row_map = {
      {"name", NormalType},
      {"uuid", NormalType},
      {"version", NormalType},
      {"path", NormalType},
      {"publisher", NormalType},
      {"publisher_id", NormalType},
      {"installed_at", NonNegativeInt},
      {"prerelease", Bool | EmptyOk},
      {"uid", NonNegativeInt},
      {"vscode_edition", NormalType},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
