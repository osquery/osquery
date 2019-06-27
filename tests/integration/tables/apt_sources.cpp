
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for apt_sources
// Spec file: specs/posix/apt_sources.table

#include <osquery/logger.h>
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
    auto const row_map = ValidatatioMap{
        {"name", NonEmptyString},
        {"source", FileOnDisk},
        {"base_uri", NonEmptyString},
        {"release", NonEmptyString},
        {"version", NonEmptyString},
        {"maintainer", NonEmptyString},
        {"components", NonEmptyString},
        {"architectures", NonEmptyString},
    };
    validate_rows(data, row_map);
  }
}

} // namespace
} // namespace table_tests
} // namespace osquery
