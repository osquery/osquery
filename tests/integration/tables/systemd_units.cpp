/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for systemd_units
// Spec file: specs/linux/systemd_units.table

#include <dbus/dbus.h>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class SystemdUnitsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(SystemdUnitsTest, test_sanity) {
  auto const data = execute_query("select * from systemd_units");

  ValidationMap row_map = {
      {"id", NormalType},
      {"description", NormalType},
      {"load_state", NormalType},
      {"active_state", NormalType},
      {"sub_state", NormalType},
      {"following", NormalType},
      {"object_path", NormalType},
      {"job_id", NormalType},
      {"job_type", NormalType},
      {"job_path", NormalType},
      {"fragment_path", NormalType},
      {"user", NormalType},
      {"source_path", NormalType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
