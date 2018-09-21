/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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

TEST_F(SystemControlsTest, sanity) {
  auto const rows = execute_query("select * from system_controls");
  auto const row_map = ValidatatioMap{
      {"name", NonEmptyString},
      {"oid", NormalType},
      {"subsystem", SpecificValuesCheck{"",
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
