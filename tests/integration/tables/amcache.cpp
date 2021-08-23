/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for registry
// Spec file: specs/windows/registry.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/system/env.h>

namespace osquery {
namespace table_tests {
namespace {

class AmcacheTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(AmcacheTest, test_sanity) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }
  auto const test_filepath =
      boost::filesystem::path(*test + "/windows/amcache/Amcache.hve")
          .make_preferred()
          .string();
  QueryData const rows = execute_query(
      "select * from amcache where source = '" + test_filepath + "'");
  ASSERT_GT(rows.size(), 0ul);
  auto const row_map = ValidationMap{
      {"path", NormalType},
      {"filename", NormalType},
      {"first_run_time", NonNegativeInt},
      {"sha1", NormalType},
      {"appx_package_fullname", NormalType},
      {"appx_package_relative_id", NormalType},
      {"binary_type", NormalType},
      {"bin_file_version", NormalType},
      {"bin_product_version", NormalType},
      {"bin_product_version", NormalType},
      {"is_os_component", NormalType},
      {"is_pe_file", NormalType},
      {"language", NormalType},
      {"link_date", NormalType},
      {"long_path_hash", NormalType},
      {"original_filename", NormalType},
      {"product_name", NormalType},
      {"product_version", NormalType},
      {"program_id", NormalType},
      {"publisher", NormalType},
      {"size", NormalType},
      {"usn", NormalType},
      {"version", NormalType},
  };
  validate_rows(rows, row_map);
}

} // namespace
} // namespace table_tests
} // namespace osquery
