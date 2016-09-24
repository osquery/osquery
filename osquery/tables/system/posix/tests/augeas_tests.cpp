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

TEST_F(AugeasTests, select_hosts_by_path_expression) {
  auto results = SQL("select * from augeas where path='/files/etc/hosts'");
  ASSERT_EQ(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("path"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("filename"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_etc_by_path_expression) {
  auto results = SQL("select * from augeas where path='/files/etc'");
  ASSERT_EQ(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("path"), "/files/etc");
  ASSERT_EQ(results.rows()[0].at("label"), "etc");
  ASSERT_TRUE(results.rows()[0].at("filename").empty())
      << "Filename is not empty. Got " << results.rows()[0].at("filename")
      << "instead";
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_by_path_expression_with_or) {
  auto results =
      SQL("select * from augeas where path='/files/etc/hosts' or "
          "path='/files/etc/resolv.conf' order by path");
  ASSERT_EQ(results.rows().size(), 2U);

  ASSERT_EQ(results.rows()[0].at("path"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("filename"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";

  ASSERT_EQ(results.rows()[1].at("path"), "/files/etc/resolv.conf");
  ASSERT_EQ(results.rows()[1].at("filename"), "/etc/resolv.conf");
  ASSERT_EQ(results.rows()[1].at("label"), "resolv.conf");
  ASSERT_TRUE(results.rows()[1].at("value").empty())
      << "Value is not empty. Got " << results.rows()[1].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_hosts_by_filename) {
  auto results = SQL("select * from augeas where filename='/etc/hosts'");
  ASSERT_GE(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("path"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("filename"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}

TEST_F(AugeasTests, select_hosts_by_label) {
  auto results = SQL("select * from augeas where label='hosts'");
  ASSERT_GE(results.rows().size(), 1U);
  ASSERT_EQ(results.rows()[0].at("path"), "/files/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("filename"), "/etc/hosts");
  ASSERT_EQ(results.rows()[0].at("label"), "hosts");
  ASSERT_TRUE(results.rows()[0].at("value").empty())
      << "Value is not empty. Got " << results.rows()[0].at("value")
      << "instead";
}
}
}
