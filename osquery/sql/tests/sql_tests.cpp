/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/format.hpp>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {

extern void escapeNonPrintableBytesEx(std::string& data);

class SQLTests : public testing::Test {};

TEST_F(SQLTests, test_raw_access) {
  // Access to the table plugins (no SQL parsing required) works in both
  // extensions and core, though with limitations on available tables.
  auto results = SQL::selectAllFrom("time");
  EXPECT_EQ(results.size(), 1U);
}

class TestTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("test_int", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("test_text", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(QueryContext& ctx) {
    QueryData results;
    if (ctx.constraints["test_int"].existsAndMatches("1")) {
      results.push_back({{"test_int", "1"}, {"test_text", "0"}});
    } else {
      results.push_back({{"test_int", "0"}, {"test_text", "1"}});
    }

    auto ints = ctx.constraints["test_int"].getAll<int>(EQUALS);
    for (const auto& int_match : ints) {
      results.push_back({{"test_int", INTEGER(int_match)}});
    }

    return results;
  }
};

TEST_F(SQLTests, test_raw_access_context) {
  auto tables = RegistryFactory::get().registry("table");
  tables->add("test", std::make_shared<TestTablePlugin>());
  auto results = SQL::selectAllFrom("test");

  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["test_text"], "1");

  results = SQL::selectAllFrom("test", "test_int", EQUALS, "1");
  EXPECT_EQ(results.size(), 2U);

  results = SQL::selectAllFrom("test", "test_int", EQUALS, "2");
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["test_int"], "2");
}

TEST_F(SQLTests, test_sql_escape) {
  std::string input = "しかたがない";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE3\\x81\\x97\\xE3\\x81\\x8B\\xE3\\x81\\x9F\\xE3\\x81\\x8C\\xE3"
            "\\x81\\xAA\\xE3\\x81\\x84");

  input = "悪因悪果";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE6\\x82\\xAA\\xE5\\x9B\\xA0\\xE6\\x82\\xAA\\xE6\\x9E\\x9C");

  input = "モンスターハンター";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input,
            "\\xE3\\x83\\xA2\\xE3\\x83\\xB3\\xE3\\x82\\xB9\\xE3\\x82\\xBF\\xE3"
            "\\x83\\xBC\\xE3\\x83\\x8F\\xE3\\x83\\xB3\\xE3\\x82\\xBF\\xE3\\x83"
            "\\xBC");

  input = "съешь же ещё этих мягких французских булок, да выпей чаю";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(
      input,
      "\\xD1\\x81\\xD1\\x8A\\xD0\\xB5\\xD1\\x88\\xD1\\x8C \\xD0\\xB6\\xD0\\xB5 "
      "\\xD0\\xB5\\xD1\\x89\\xD1\\x91 \\xD1\\x8D\\xD1\\x82\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xBC\\xD1\\x8F\\xD0\\xB3\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD1\\x84\\xD1\\x80\\xD0\\xB0\\xD0\\xBD\\xD1\\x86\\xD1\\x83\\xD0\\xB7\\"
      "xD1\\x81\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xB1\\xD1\\x83\\xD0\\xBB\\xD0\\xBE\\xD0\\xBA, "
      "\\xD0\\xB4\\xD0\\xB0 \\xD0\\xB2\\xD1\\x8B\\xD0\\xBF\\xD0\\xB5\\xD0\\xB9 "
      "\\xD1\\x87\\xD0\\xB0\\xD1\\x8E");

  input = "The quick brown fox jumps over the lazy dog.";
  escapeNonPrintableBytesEx(input);
  EXPECT_EQ(input, "The quick brown fox jumps over the lazy dog.");
}

TEST_F(SQLTests, test_sql_base64_encode) {
  QueryData d;
  query("select to_base64('test') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "dGVzdA==");
}

TEST_F(SQLTests, test_sql_base64_decode) {
  QueryData d;
  query("select from_base64('dGVzdA==') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");
}

TEST_F(SQLTests, test_sql_base64_conditional_encode) {
  QueryData d;
  query("select conditional_to_base64('test') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");

  QueryData d2;
  query("select conditional_to_base64('悪因悪果') as test;", d2);
  EXPECT_EQ(d2.size(), 1U);
  EXPECT_EQ(d2[0]["test"], "5oKq5Zug5oKq5p6c");
}

TEST_F(SQLTests, test_sql_md5) {
  QueryData d;
  query("select md5('test') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "098f6bcd4621d373cade4e832627b4f6");
}

TEST_F(SQLTests, test_sql_sha1) {
  QueryData d;
  query("select sha1('test') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
}

TEST_F(SQLTests, test_sql_sha256) {
  QueryData d;
  query("select sha256('test') as test;", d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

#ifdef OSQUERY_POSIX
TEST_F(SQLTests, test_sql_ssdeep_compare) {
  QueryData d;
  // random 32KB file vs same file concatenated with another random 32KB file
  std::stringstream query_stream;
  query_stream << boost::format(
                      "select ssdeep_compare('%s', '%s') as test_int;") %
                      "768:hRWoDxStE/p76XkJx2HIjxZ2bhX+wQp+uCRdONCGav/"
                      "IGdBR:aoD582YotZMLQp+5RdONCGM/BR" %
                      "1536:aoD582YotZMLQp+5RdONCGM/BnxFEu4vNz/xC+Oi+u/UD/"
                      "9LYD:h22YWZVsRBGMZndQNz/xCfi+qeYD";
  query(query_stream.str(), d);
  EXPECT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test_int"], "68");
}
#endif
}
