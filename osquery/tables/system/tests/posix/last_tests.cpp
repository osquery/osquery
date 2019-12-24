/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <fstream>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>

#include <osquery/tables/system/posix/last.h>
#include <osquery/utils/scope_guard.h>

#include <utmp.h>
#include <pwd.h>

namespace osquery {
namespace tables {

class LastImplTests : public testing::Test {};

TEST_F(LastImplTests, gen_row_from_utmpx) {
  QueryData results;
  struct utmpx ut_login;
  struct utmpx ut_badtype;
  struct utmpx ut_logout;

  ut_login.ut_user = "osquery";
  ut_login.ut_line = "line";
  ut_login.ut_type = USER_PROCESS;
  ut_login.ut_pid = 1337;
  ut_login.ut_tv.tv_sec = 1577836800;
  ut_login.ut_host = "test_host";

  ut_badtype.ut_type = INIT_PROCESS;

  ut_logout.ut_line = "line";
  ut_logout.ut_type = DEAD_PROCESS;
  ut_logout.ut_pid = 1337;
  ut_logout.ut_tv.tv_sec = 1577836900;

  impl::genLastAccessForRow(&ut_login, results);
  impl::genLastAccessForRow(&ut_badtype, results);
  impl::genLastAccessForRow(&ut_logout, results);

  ASSERT_EQ(results.size(), 2);

  const auto& first_row = results[0];
  EXPECT_EQ(first_row.at("username"), ut_login.ut_user);
  EXPECT_EQ(first_row.at("tty"), ut_login.ut_user);
  EXPECT_EQ(first_row.at("pid"), ut_login.ut_pid);
  EXPECT_EQ(first_row.at("type"), ut_login.ut_type);
  EXPECT_EQ(first_row.at("host"), ut_login.ut_host);

  const auto& second_row = results[1];
  EXPECT_EQ(second_row.at("username"), "");
  EXPECT_EQ(second_row.at("tty"), ut_logout.ut_user);
  EXPECT_EQ(second_row.at("pid"), ut_logout.ut_pid);
  EXPECT_EQ(second_row.at("type"), ut_logout.ut_type);
  EXPECT_EQ(second_row.at("host"), "");
}

} // namespace tables
} // namespace osquery
