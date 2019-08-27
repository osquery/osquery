/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/database.h>
#include <osquery/registry.h>
#include <osquery/system.h>

namespace osquery {

DECLARE_bool(disable_database);

class ViewsConfigParserPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      Initializer::platformSetup();
      registryAndPluginInit();

      // Force registry to use ephemeral database plugin
      FLAGS_disable_database = true;
      DatabasePlugin::setAllowOpen(true);
      DatabasePlugin::initPlugin();
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
