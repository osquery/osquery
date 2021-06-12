/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/system/env.h>

#include <string>

namespace osquery {
namespace table_tests {
class JumplistsTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(JumplistsTest, test_sanity) {
  auto test = getEnvVar("TEST_CONF_FILES_DIR");
  if (!test.is_initialized()) {
    FAIL();
  }

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"entry", IntType},
      {"target_path", NormalType},
      {"target_modified", IntType},
      {"target_created", IntType},
      {"target_accessed", IntType},
      {"app_id", NormalType},
      {"app_name", NormalType},
      {"interaction_count", IntType},
      {"relative_path", NormalType},
      {"local_path", NormalType},
      {"working_path", NormalType},
      {"icon_path", NormalType},
      {"common_path", NormalType},
      {"command_args", NormalType},
      {"hostname", NormalType},
      {"share_name", NormalType},
      {"device_type", NormalType},
      {"volume_serial", NormalType},
      {"mft_entry", IntType},
      {"mft_sequence", IntType},
      {"description", NormalType},

  };

  auto const test_filepath =
      boost::filesystem::path(*test + "\\windows\\jumplists\\automatic\\%")
          .make_preferred()
          .string();
  std::string query =
      "select * from jumplists where path like '" + test_filepath + "'";
  QueryData const rows = execute_query(query);

  ASSERT_GT(rows.size(), 0ul);
  validate_rows(rows, row_map);

  QueryData const default_rows = execute_query("select * from jumplists");
  if (!default_rows.empty()) {
    ASSERT_GT(default_rows.size(), 0ul);
    validate_rows(default_rows, row_map);
  }
}
} // namespace table_tests
} // namespace osquery