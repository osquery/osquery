/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for apt_sources
// Spec file: specs/linux/apt_sources.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {
namespace {

class AptSourcesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(AptSourcesTest, test_sanity) {
  QueryData data = execute_query("select * from apt_sources");
  if (data.empty()) {
    LOG(WARNING) << "select from \"apt_sources\" table returned no results and "
                    "therefore won't be tested";
  } else {
    auto const row_map = ValidationMap{
        {"name", NonEmptyString},
        {"source", FileOnDisk},
        {"base_uri", NonEmptyString},
        {"release", NormalType},
        {"version", NormalType},
        {"maintainer", NonEmptyString},
        {"components", NormalType},
        {"architectures", NonEmptyString},
    };
    validate_rows(data, row_map);
  }
}

} // namespace
} // namespace table_tests
} // namespace osquery
