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

#include <fstream>

#include <boost/filesystem.hpp>

#include <osquery/core/flags.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/system/env.h>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(magic_db_files);

namespace table_tests {

class magic : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    saved_magic_db_files_ = FLAGS_magic_db_files;
    dir_ = fs::temp_directory_path() /
           fs::unique_path("osquery.tests.magic.%%%%.%%%%");
    ASSERT_TRUE(fs::create_directories(dir_));

    // A compiled database of another format version, as systems ship.
    // Loaded, libmagic would parse it as rules and print a warning for each
    // line. MAGICNO and format version 16, little-endian.
    other_version_db_ = (dir_ / "magic.mgc").string();
    const char header[] = {
        '\x1c', '\x04', '\x1e', '\xf1', '\x10', '\x00', '\x00', '\x00'};
    std::ofstream stream(other_version_db_, std::ios::binary);
    stream.write(header, sizeof(header));
    stream << std::string(64, '\x7f');
  }

  void TearDown() override {
    FLAGS_magic_db_files = saved_magic_db_files_;
    fs::remove_all(dir_);
  }

  std::string saved_magic_db_files_;
  fs::path dir_;
  std::string other_version_db_;
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

  auto const data =
      execute_query("select * from magic where path = '" + *magic_db +
                    "' and magic_db_files = '" + *magic_db + "'");
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

TEST_F(magic, test_default_list_skips_unloadable_databases) {
  auto magic_db = getEnvVar("TEST_MAGIC_DB");
  if (!magic_db.is_initialized()) {
    GTEST_SKIP() << "TEST_MAGIC_DB is not set";
  }

  FLAGS_magic_db_files = other_version_db_ + ":" + *magic_db + ":" +
                         (dir_ / "missing.mgc").string();
  auto const data =
      execute_query("select * from magic where path = '" + *magic_db + "'");
  ASSERT_EQ(data.size(), 1ul);

  // Only the bundled database is loaded
  EXPECT_EQ(data[0].at("magic_db_files"), *magic_db);

  ValidationMap row_map = {
      {"path", NonEmptyString},
      {"magic_db_files", NonEmptyString},
      {"data", NonEmptyString},
      {"mime_type", NonEmptyString},
      {"mime_encoding", NonEmptyString},
  };
  validate_rows(data, row_map);
}

TEST_F(magic, test_default_list_without_loadable_database) {
  // Nothing in the list can be loaded: the table returns no rows.
  FLAGS_magic_db_files =
      other_version_db_ + ":" + (dir_ / "missing.mgc").string();
  auto const data = execute_query("select * from magic where path = '" +
                                  other_version_db_ + "'");
  EXPECT_TRUE(data.empty());
}

} // namespace table_tests
} // namespace osquery
