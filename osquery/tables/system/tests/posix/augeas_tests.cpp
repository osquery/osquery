/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

namespace osquery {

DECLARE_string(augeas_lenses);

namespace tables {

class AugeasTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    FLAGS_augeas_lenses =
        (osquery::getTestConfigDirectory() / "augeas/lenses").string();
  }
};

TEST_F(AugeasTests, select_hosts_by_path_expression) {
  auto results =
      SQL("select * from augeas where path = '/etc/hosts' and label = 'hosts' "
          "limit 1");
  ASSERT_EQ(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("node"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("path"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_etc_folder_by_path_expression) {
  auto results = SQL("select * from augeas where path = '/etc' limit 1");
  ASSERT_EQ(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("node"), "/files/etc");
  ASSERT_EQ(results.rows()[0].at("label"), "etc");
  ASSERT_EQ(results.rows()[0].at("path"), "/etc");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_files_by_path_expression_with_or) {
  auto results =
      SQL("select * from augeas where path = '/etc/hosts' or "
          "path = '/etc/resolv.conf' group by path order by path");

  ASSERT_EQ(results.rows().size(), 2U);
  ASSERT_EQ(results.rows()[0].at("path"), "/etc/hosts");
  ASSERT_EQ(results.rows()[1].at("path"), "/etc/resolv.conf");
}

TEST_F(AugeasTests, select_files_by_path_or_node) {
  auto results =
      SQL("select * from augeas where node = '/files/etc/hosts' or "
          "path = '/etc/resolv.conf' group by path order by path");

  ASSERT_EQ(results.rows().size(), 2U);
  ASSERT_EQ(results.rows()[0].at("node"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[1].at("path"), "/etc/resolv.conf");
}

TEST_F(AugeasTests, select_hosts_by_node) {
  auto results = SQL("select * from augeas where node = '/files/etc/hosts'");
  ASSERT_GE(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("node"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("path"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}
} // namespace tables
} // namespace osquery
