/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for magic
// Spec file: specs/posix/magic.table

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/system/env.h>

namespace osquery {
namespace table_tests {

class magic : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(magic, test_sanity) {
  // The build compiles a magic database matching the vendored libmagic into
  // the build tree; the CTest registration passes its path as TEST_MAGIC_DB.
  // Querying the database file itself is platform-neutral: any libmagic
  // identifies its own compiled database.
  auto magic_db = getEnvVar("TEST_MAGIC_DB");
  if (!magic_db.is_initialized()) {
    GTEST_SKIP() << "TEST_MAGIC_DB is not set";
  }

  auto const data = execute_query("select * from magic where path = '" +
                                  *magic_db + "' and magic_db_files = '" +
                                  *magic_db + "'");
  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"magic_db_files", NonEmptyString},
      {"data", NonEmptyString},
      {"mime_type", NonEmptyString},
      {"mime_encoding", NonEmptyString},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
