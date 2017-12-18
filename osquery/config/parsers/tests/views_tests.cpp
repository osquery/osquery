/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class ViewsConfigParserPluginTests : public testing::Test {};

TEST_F(ViewsConfigParserPluginTests, test_add_view) {
  Config c;
  auto s = c.update(getTestConfigMap());
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
