/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>

namespace osquery {

class ViewsConfigParserPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      platformSetup();
      registryAndPluginInit();
      initDatabasePluginForTesting();
    }
  }
};

TEST_F(ViewsConfigParserPluginTests, test_add_view) {
  Config c;
  auto s = c.update(getTestConfigMap("test_parse_items.conf"));
  EXPECT_TRUE(s.ok());

  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  c.reset();
}

TEST_F(ViewsConfigParserPluginTests, test_swap_view) {
  Config c;
  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  old_views_vec.clear();
  auto s = c.update(getTestConfigMap("view_test.conf"));
  EXPECT_TRUE(s.ok());
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  EXPECT_EQ(old_views_vec[0], "config_views.kernel_hashes_new");

  c.reset();
}

TEST_F(ViewsConfigParserPluginTests, test_update_view) {
  Config c;
  std::vector<std::string> old_views_vec;
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  old_views_vec.clear();
  auto s = c.update(getTestConfigMap("view_test2.conf"));
  EXPECT_TRUE(s.ok());
  scanDatabaseKeys(kQueries, old_views_vec, "config_views.");
  EXPECT_EQ(old_views_vec.size(), 1U);
  std::string query;
  getDatabaseValue(kQueries, "config_views.kernel_hashes_new", query);
  EXPECT_EQ(query,
            "select hash.path as binary, version, hash.sha256 as SHA256, "
            "hash.sha1 as SHA1, hash.md5 as MD5 from (select path || "
            "'/Contents/MacOS/' as directory, name, version from "
            "kernel_extensions) join hash using (directory)");

  c.reset();
}
}
