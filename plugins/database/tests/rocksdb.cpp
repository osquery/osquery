/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/sql/sql.h>
#include <plugins/database/rocksdb.h>

namespace osquery {

class RocksDBDatabasePluginTests : public DatabasePluginTests {
 protected:
  std::string name() override {
    return "rocksdb";
  }
};

// Define the default set of database plugin operation tests.
CREATE_DATABASE_TESTS(RocksDBDatabasePluginTests);

TEST_F(RocksDBDatabasePluginTests, test_rocksdb_loglevel) {
  // Make sure a log file was created.
  EXPECT_FALSE(pathExists(path_ + "/LOG"));

  // Make sure no log file is created.
  // RocksDB logs are intercepted and forwarded to the GLog sink.
  auto details = SQL::selectAllFrom("file", "path", EQUALS, path_ + "/LOG");
  ASSERT_EQ(details.size(), 0U);
}

TEST_F(RocksDBDatabasePluginTests, test_corruption) {
  ASSERT_TRUE(pathExists(path_));
  ASSERT_FALSE(pathExists(path_ + ".backup"));

  // Mark the database as corrupted
  RocksDBDatabasePlugin::setCorrupted();
  resetDatabase();

  EXPECT_TRUE(pathExists(path_ + ".backup"));

  // Remove the backup and expect another reload to not create one.
  removePath(path_ + ".backup");
  ASSERT_FALSE(pathExists(path_ + ".backup"));

  resetDatabase();
  EXPECT_FALSE(pathExists(path_ + ".backup"));
}
}
