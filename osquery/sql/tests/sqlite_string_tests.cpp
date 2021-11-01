/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/system/env.h>

#include <gtest/gtest.h>

namespace osquery {
class SQLitePlatformTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();

    setEnvVar("OSQUERY_TEST", "TEST_VARIABLE");
  }
};

TEST_F(SQLitePlatformTests, test_expand_with_no_variable) {
  std::string input_variable;
#ifdef WIN32
  input_variable = "%NoVariable%";
#else
  input_variable = "$NoVariable";
#endif

  Row r;
  r["var"] = input_variable;

  SQL sql = SQL("SELECT expand_env(\"" + input_variable + "\") AS var");

#ifdef WIN32
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
#else
  EXPECT_FALSE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 0U);
#endif
}

TEST_F(SQLitePlatformTests, test_expand_with_no_specifier) {
  Row r;
  r["var"] = "NoVariable";

  SQL sql = SQL("SELECT expand_env(\"NoVariable\") AS var");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLitePlatformTests, test_expand_with_variable) {
  Row r;
  r["var"] = "TEST_VARIABLE-WITH_TEST_STRING";
  std::string input_variable;
#ifdef WIN32
  input_variable = "%OSQUERY_TEST%";
#else
  input_variable = "$OSQUERY_TEST";
#endif

  SQL sql = SQL("SELECT expand_env(\"" + input_variable +
                "-WITH_TEST_STRING\") AS var");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);

#ifndef WIN32
  input_variable = "${OSQUERY_TEST}";

  sql = SQL("SELECT expand_env(\"" + input_variable +
            "-WITH_TEST_STRING\") AS var");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0], r);
#endif
}
} // namespace osquery
