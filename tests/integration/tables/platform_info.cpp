/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for platform_info
// Spec file: specs/platform_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery::table_tests {

class platformInfo : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(platformInfo, test_sanity) {
  auto const data = execute_query("select * from platform_info");

  ValidationMap row_map = {
    {"vendor", NormalType},
    {"version", NormalType},
    {"extra", NormalType},
    {"date", NormalType},
    {"revision", NormalType},

#ifndef OSQUERY_WINDOWS
    {"address", NormalType},
    {"size", IntOrEmpty},
    {"volume_size", NonNegativeInt},
#endif

#if defined(__APPLE__) || defined(OSQUERY_WINDOWS)
    {"firmware_type", NonEmptyString},
#endif
  };

  validate_rows(data, row_map);
}

} // namespace osquery::table_tests
