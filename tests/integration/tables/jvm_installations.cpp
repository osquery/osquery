/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for jvm_installations
// Spec file: specs/jvm_installations.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

class jvmPackages : public testing::Test {
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

TEST_F(jvmPackages, test_sanity) {
  ValidationMap row_map = {
      {"name", NormalType},
      {"uid", IntType},
      {"version", NormalType},
      {"vendor", NormalType},
      {"path", NormalType},
      {"architecture", NormalType},
  };

  auto const data = execute_query("select * from jvm_installations");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery