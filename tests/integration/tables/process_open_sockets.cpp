/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for process_open_sockets
// Spec file: specs/process_open_sockets.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class processOpenSockets : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(processOpenSockets, test_sanity) {
  ValidationMap row_map = {
      {"pid", IntType},
      {"fd", IntOrEmpty},
      {"socket", IntOrEmpty},
      {"family", IntType},
      {"protocol", IntType},
      {"local_address", NormalType},
      {"remote_address", NormalType},
      {"local_port", IntType},
      {"remote_port", IntType},
      {"path", NormalType},
      {"state", NormalType},
  };

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    row_map["net_namespace"] = IntType;
  }

  auto const data = execute_query("select * from process_open_sockets");
  ASSERT_FALSE(data.empty());
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
