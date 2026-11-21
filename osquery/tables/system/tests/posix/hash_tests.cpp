/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/stat.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <string>
#include <thread>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/scope_guard.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

class HashTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(HashTests, test_cache_rehashes_rewritten_file_with_restored_mtime) {
  auto path = fs::temp_directory_path() /
              fs::unique_path("osquery.hash_tests.%%%%-%%%%");

  auto const path_guard = scope_guard::create([path]() { fs::remove(path); });

  auto write = [&path](char fill) {
    std::ofstream fout(path.native());
    fout << std::string(64, fill);
  };
  write('A');

  const std::string query =
      "select sha256 from hash where path = '" + path.string() + "'";

  SQL before(query);
  ASSERT_TRUE(before.ok());
  ASSERT_EQ(before.rows().size(), 1U);
  EXPECT_EQ(before.rows()[0].at("sha256"),
            "d53eda7a637c99cc7fb566d96e9fa109bf15c478410a3f5eb4d4c4e26cd081f6");

  // The cache compares timestamps in whole seconds, so let the clock move past
  // the second the file was created in before changing it.
  struct stat st;
  ASSERT_EQ(stat(path.c_str(), &st), 0);
  while (std::time(nullptr) <= st.st_ctime) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  // Rewrite the content in place, keeping the inode and the size, and put the
  // modification time back the way a timestomping tool would.
  const auto mtime = fs::last_write_time(path);
  write('B');
  fs::last_write_time(path, mtime);

  SQL after(query);
  ASSERT_TRUE(after.ok());
  ASSERT_EQ(after.rows().size(), 1U);
  EXPECT_EQ(after.rows()[0].at("sha256"),
            "c422e7070cb1cb455b5de9afee0d975e303d0239c72030cd7414ab5c382d3ae8");
}

} // namespace tables
} // namespace osquery
