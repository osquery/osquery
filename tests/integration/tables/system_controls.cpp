/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for system_controls
// Spec file: specs/posix/system_controls.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
namespace {

class SystemControlsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SystemControlsTest, test_sanity) {
  auto const rows = execute_query("select * from system_controls");
  auto const row_map = ValidationMap{
      {"name", NonEmptyString},
      {"oid", NormalType},
      {"subsystem",
       SpecificValuesCheck{"",
                           "abi",
                           "debug",
                           "dev",
                           "fs",
                           "fscache",
                           "hw",
                           "kern",
                           "kernel",
                           "machdep",
                           "net",
                           "sunrpc",
                           "user",
                           "vfs",
                           "vm"}},
      {"current_value", NormalType},
      {"config_value", NormalType},
      {"type",
       SpecificValuesCheck{
           "", "node", "int", "string", "quad", "opaque", "struct"}},
#ifdef __APPLE__
      {"field_name", NormalType},
#endif
  };
  validate_rows(rows, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
