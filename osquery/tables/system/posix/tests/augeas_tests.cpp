/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/sql.h>

namespace osquery {
namespace tables {

class AugeasTests : public testing::Test {};

TEST_F(AugeasTests, sanity_test) {
  auto results = SQL("select * from augeas");
  for (auto row : results.rows()) {
    auto node = row.at("node");
    auto path = row.at("path");
    auto label = row.at("label");
    ASSERT_FALSE(node.empty()) << "Node is empty!";
    ASSERT_TRUE(node.find(path) != std::string::npos)
        << "Path not in node. Path=" << path
        << " Node=" << node;
    // Deal with escaping issues
    for(size_t pos = 0; (pos = node.find("\\", pos)) != std::string::npos; pos += 1) {
      node.replace(pos, 1, "");
    }
    ASSERT_TRUE(node.find(label) != std::string::npos)
        << "Label not in node. Label=" << label
        << " Node=" << node;
  }
}

TEST_F(AugeasTests, select_hosts_by_path_expression) {
  auto results = SQL("select * from augeas where path = '/etc/hosts' limit 1");
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
