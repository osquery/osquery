/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/format.hpp>
#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/tests/sql_test_utils.h>

namespace osquery {

extern void escapeNonPrintableBytesEx(std::string& data);

class SQLTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
  }
};

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

  TableRows generate(QueryContext& ctx) {
    TableRows results;
    if (ctx.constraints["test_int"].existsAndMatches("1")) {
      results.push_back(
          make_table_row({{"test_int", "1"}, {"test_text", "0"}}));
    } else {
      results.push_back(
          make_table_row({{"test_int", "0"}, {"test_text", "1"}}));
    }

    auto ints = ctx.constraints["test_int"].getAll<int>(EQUALS);
    for (const auto& int_match : ints) {
      results.push_back(make_table_row({{"test_int", INTEGER(int_match)}}));
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
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "dGVzdA==");
}

TEST_F(SQLTests, test_sql_base64_decode) {
  QueryData d;
  query("select from_base64('dGVzdA==') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");
}

TEST_F(SQLTests, test_sql_base64_conditional_encode) {
  QueryData d;
  query("select conditional_to_base64('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "test");

  QueryData d2;
  query("select conditional_to_base64('悪因悪果') as test;", d2);
  ASSERT_EQ(d2.size(), 1U);
  EXPECT_EQ(d2[0]["test"], "5oKq5Zug5oKq5p6c");
}

TEST_F(SQLTests, test_sql_md5) {
  QueryData d;
  query("select md5('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "098f6bcd4621d373cade4e832627b4f6");
}

TEST_F(SQLTests, test_sql_sha1) {
  QueryData d;
  query("select sha1('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
}

TEST_F(SQLTests, test_sql_sha256) {
  QueryData d;
  query("select sha256('test') as test;", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

/*
 * regex_match
 */

TEST_F(SQLTests, test_regex_match_multiple) {
  QueryData d;

  query(
      "select regex_match('hello world', '(l)(o).*', 0) as t0, \
                regex_match('hello world', '(l)(o).*', 1) as t1, \
                regex_match('hello world', '(l)(o).*', 2) as t2, \
                regex_match('hello world', '(l)(o).*', 3) as t3;",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "lo world");
  EXPECT_EQ(d[0]["t1"], "l");
  EXPECT_EQ(d[0]["t2"], "o");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_match_nomatch) {
  QueryData d;

  query(
      "select regex_match('hello world', 'no match', 0) as t0 \
                regex_match('hello world', 'no match', 1) as t1;",
      d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_complex) {
  QueryData d;

  query(
      "select regex_match('hello world', '(\\w+) .*(or|ld)', 0) as t0, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 1) as t1, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 2) as t2, \
                regex_match('hello world', '(\\w+) .*(or|ld)', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "hello world");
  EXPECT_EQ(d[0]["t1"], "hello");
  EXPECT_EQ(d[0]["t2"], "ld");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_match_fileextract) {
  QueryData d;

  query(
      "select regex_match('/filesystem/path/download.extension.zip', "
      "'.+/([^./]+)', 1) as basename",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["basename"], "download");
}

TEST_F(SQLTests, test_regex_match_empty) {
  QueryData d;
  // Empty regex gets you a null result
  query("select regex_match('hello world', '', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "");
}

TEST_F(SQLTests, test_regex_match_invalid1) {
  QueryData d;
  query("select regex_match('foo/bar', '(/', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_invalid2) {
  QueryData d;
  query("select regex_match('foo/bar', '+', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_match_invalid3) {
  QueryData d;
  // `|` is an invalid regexp but std::basic_regex doesn't complain, and treats
  // it much as an empty string. Encode that exception here in tests.
  query("select regex_match('foo/bar', '|', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);

  std::string query_result;
  ASSERT_NO_THROW(query_result = d[0].at("test"));
  ASSERT_TRUE(query_result.empty());
}

TEST_F(SQLTests, test_regex_match_too_big) {
  QueryData d;
  std::string regex(100000, '|');
  auto status = query("select regex_match('foo/bar', '" + regex + "', 0)", d);
  ASSERT_TRUE(!status.ok());
  std::string error_too_big = "Invalid regex: too big";
  ASSERT_EQ(status.getMessage().compare(0, error_too_big.size(), error_too_big),
            0);
}

/*
 * split
 */

TEST_F(SQLTests, test_split_slash) {
  QueryData d;

  query(
      "select split('/foo/bar', '/', 0) as t0, \
                split('/foo/bar', '/', 1) as t1, \
                split('/foo/bar', '/', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_split_double_semicolon) {
  QueryData d;

  query(
      "select split('foo;;bar', ';;', 0) as t0, \
                split('foo;;bar', ';;', 1) as t1, \
                split('foo;;bar', ';;', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_split_empty) {
  QueryData d;

  query("select split('foo;;bar', '', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

/*
 * regex_split
 */

TEST_F(SQLTests, test_regex_split_slashes) {
  QueryData d;

  query(
      "select regex_split('/foo/bar', '/', 0) as t0, \
                regex_split('/foo/bar', '/', 1) as t1, \
                regex_split('/foo/bar', '/', 2) as t2, \
                regex_split('/foo/bar', '/', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "");
  EXPECT_EQ(d[0]["t1"], "foo");
  EXPECT_EQ(d[0]["t2"], "bar");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_split_double_semicolon) {
  QueryData d;

  query(
      "select regex_split('foo;;bar', ';;', 0) as t0, \
                regex_split('foo;;bar', ';;', 1) as t1, \
                regex_split('foo;;bar', ';;', 2) as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "");
}

TEST_F(SQLTests, test_regex_split_options) {
  QueryData d;

  query(
      "select regex_split('foo;bar//qux', '(;|/)+', 0) as t0, \
                regex_split('foo;bar//qux', '(;|/)+', 1) as t1, \
                regex_split('foo;bar//qux', '(;|/)+', 2) as t2, \
                regex_split('foo;bar//qux', '(;|/)+', 3) as t3",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "foo");
  EXPECT_EQ(d[0]["t1"], "bar");
  EXPECT_EQ(d[0]["t2"], "qux");
  EXPECT_EQ(d[0]["t3"], "");
}

TEST_F(SQLTests, test_regex_split_filename_extract) {
  QueryData d;
  // A more complex example.
  query(
      "select regex_split('/filesystem/path/download.extension.zip', "
      "'(.*/)|(.extension.zip)', 1) as test",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["test"], "download");
}

TEST_F(SQLTests, test_regex_split_empty) {
  QueryData d;
  query("select regex_split('foo/bar', '', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_invalid1) {
  QueryData d;
  query("select regex_split('foo/bar', '(/', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_invalid2) {
  QueryData d;
  query("select regex_split('foo/bar', '+', 0)", d);
  ASSERT_EQ(d.size(), 0U);
}

TEST_F(SQLTests, test_regex_split_with_or) {
  QueryData d;
  // `|` is an invalid regexp but std::basic_regex doesn't complain, and treats
  // it much as an empty string. Encode that exception here in tests.
  query("select regex_split('foo/bar', '|', 0) as test", d);
  ASSERT_EQ(d.size(), 1U);

  std::string query_result;
  ASSERT_NO_THROW(query_result = d[0].at("test"));
  ASSERT_TRUE(query_result.empty());
}

TEST_F(SQLTests, test_regex_split_too_big) {
  QueryData d;
  std::string regex(100000, '|');
  auto status = query("select regex_split('foo/bar', '" + regex + "', 0)", d);
  ASSERT_TRUE(!status.ok());
}

/*
 * concat
 */
TEST_F(SQLTests, test_concat) {
  QueryData d;

  auto status = query(
      "select concat() as t0, \
              concat('hello') as t1, \
              concat('hello', 'world') as t2, \
              concat('hello', NULL, 'world') as t3, \
              concat(1, 2, 3, 'go') as t4, \
              concat('') as t5",
      d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "");
  EXPECT_EQ(d[0]["t1"], "hello");
  EXPECT_EQ(d[0]["t2"], "helloworld");
  EXPECT_EQ(d[0]["t3"], "helloworld");
  EXPECT_EQ(d[0]["t4"], "123go");
  EXPECT_EQ(d[0]["t5"], "");
}

/*
 * concat_ws
 */
TEST_F(SQLTests, test_concat_ws) {
  QueryData d;

  auto status = query(
      "select concat_ws('') as t0, \
              concat_ws(NULL) as t1, \
              concat_ws(', ', 'hello', 'world', 1, 2, 3) as t2, \
              concat_ws('', 'hello', 'world', 1, 2, 3) as t3, \
              concat_ws(NULL, 'hello', 'world', 1, 2, 3) as t4, \
              concat_ws(' ', 'hello', NULL, 'world') as t5, \
              concat_ws('x', 'hello') as t6, \
              concat_ws('x', '', '') as t7",

      d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "");
  EXPECT_EQ(d[0]["t1"], "");
  EXPECT_EQ(d[0]["t2"], "hello, world, 1, 2, 3");
  EXPECT_EQ(d[0]["t3"], "helloworld123");
  EXPECT_EQ(d[0]["t4"], "helloworld123");
  EXPECT_EQ(d[0]["t5"], "hello world");
  EXPECT_EQ(d[0]["t6"], "hello");
  EXPECT_EQ(d[0]["t7"], "x");
}

TEST_F(SQLTests, test_concat_ws_fail) {
  QueryData d;

  auto status = query("select concat_ws()", d);
  ASSERT_TRUE(!status.ok());
}

/*
 * version_compare
 */
TEST_F(SQLTests, test_version_compare) {
  QueryData d;
  auto status = query(
      "select version_compare('1.0', '1.0') as t0, \
              version_compare('1:2.0-10', '1:2.0-10', 'DPKG') as t1, \
              version_compare('4:1.1.0', '4:1.1.0-3', 'arCH') as t2, \
              version_compare('50.4.1b', '50.4.1c') as t3, \
              version_compare('1.0.8-4', '1.0.8-6', 'arch') as t4, \
              version_compare('1.0.0~rc2^2021', '1.0.0', 'RHEL') as t5, \
              version_compare('1.1.0~BETA2^1', '1.1.0~CR1', 'RhEl') as t6, \
              version_compare('1.0.1.1', '1.0.1^2021', 'rhel') as t7, \
              version_compare('1.9.9-1ubuntu2.4', '1.9.9-1ubuntu2.3', 'dpkg') as t8, \
              version_compare('1:1.2.13-2', '4.2.1', 'ARCH') as t9, \
              version_compare('106.32.1', '106:32.1') as t10",
      d);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "0");
  EXPECT_EQ(d[0]["t1"], "0");
  EXPECT_EQ(d[0]["t2"], "0");
  EXPECT_EQ(d[0]["t3"], "-1");
  EXPECT_EQ(d[0]["t4"], "-1");
  EXPECT_EQ(d[0]["t5"], "-1");
  EXPECT_EQ(d[0]["t6"], "-1");
  EXPECT_EQ(d[0]["t7"], "1");
  EXPECT_EQ(d[0]["t8"], "1");
  EXPECT_EQ(d[0]["t9"], "1");
  EXPECT_EQ(d[0]["t10"], "0");
}

/*
 * collate version
 */
TEST_F(SQLTests, test_collate_version_eq) {
  QueryData d;
  // 1:0.0 = 1.0.0 - This is to showcase that if delimiter_precedence = false,
  // delimiters will be equal.
  auto status = query(
      "select '1.0' = '1.0' collate version as t0, \
              '1:0.0' = '1.0.0' collate version as t1, \
              '2.50^1a' = '2.50~1a' collate version as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
}

TEST_F(SQLTests, test_collate_version_lt) {
  QueryData d;
  auto status = query(
      "select '1.0' < '1.1' collate version as t0, \
              '1.1' < '1.a' collate version as t1, \
              '50.4.1b' < '50.4.1c' collate version as t2, \
              '1.0.0' < '1.0.0-2' collate version as t3, \
              '1.0.0-2' < '1:0.0.3' collate version as t4, \
              '1.12.1' < '1.13' collate version as t5",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
}

TEST_F(SQLTests, test_collate_version_gt) {
  QueryData d;
  auto status = query(
      "select '1.1' > '1.0' collate version as t0, \
              '190.10a' > '20.10a' collate version as t1, \
              '20.10a' > '20.102' collate version as t2, \
              '57:4' > '6.87.5' collate version as t3, \
              '98.100.21-1b' > '98.100.21-1a' collate version as t4, \
              '8.11' > '8.10.24' collate version as t5",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
}

/*
 * collate version arch
 */
TEST_F(SQLTests, test_collate_version_arch_eq) {
  QueryData d;
  auto status = query(
      "select '1.0' = '1.0' collate version_arch as t0, \
              '1.0' = '1.0-4' collate version_arch as t1, \
              '4:2' = '4:2-1' collate version_arch as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
}

TEST_F(SQLTests, test_collate_version_arch_lt) {
  QueryData d;
  auto status = query(
      "select '1.0' < '1.1' collate version_arch as t0, \
              '1.6.1-9' < '1.6.1-10' collate version_arch as t1, \
              '20220713-1' < '20221123-1' collate version_arch as t2, \
              '2-2pre' < '2-2rc' collate version_arch as t3, \
              '2.38-6' < '2.39-4' collate version_arch as t4, \
              '1.0.8-4' < '1.0.8-5' collate version_arch as t5, \
              '20210603-1' < '20220905-1' collate version_arch as t6, \
              '41.1-2' < '43alpha+r8+g1de47dbc-1' collate version_arch as t7, \
              '9.1-1' < '9.1-3' collate version_arch as t8, \
              '1:42.3.1-1' < '1:43.2-1' collate version_arch as t9, \
              '42.3-1' < '43.2-1' collate version_arch as t10",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
  EXPECT_EQ(d[0]["t6"], "1");
  EXPECT_EQ(d[0]["t7"], "1");
  EXPECT_EQ(d[0]["t8"], "1");
  EXPECT_EQ(d[0]["t9"], "1");
  EXPECT_EQ(d[0]["t10"], "1");
}

TEST_F(SQLTests, test_collate_version_arch_gt) {
  QueryData d;
  auto status = query(
      "select '1.1' > '1.0' collate version_arch as t0, \
              '3.46.7-1' > '3.44.1-1' collate version_arch as t1, \
              '6.0.12.arch1-1' > '5.18.14.arch1-1' collate version_arch as t2, \
              '5.6.0-2' > '5.3.0-2' collate version_arch as t3, \
              '6.0.2-5' > '6.0.1-5' collate version_arch as t4, \
              '3:0.164.r3095.baee400-4' > '3:0.164.r3081.19856cc-2' collate version_arch as t5, \
              '2022.2-1' > '2022.1-1' collate version_arch as t6, \
              '5.2.9-1' > '5.2.5-3' collate version_arch as t7, \
              '42.2-1' > '42.1-2' collate version_arch as t8, \
              '0.23.90-1' > '0.23.1-9' collate version_arch as t9, \
              '1:1.2.13-2' > '4.2.1' collate version_arch as t10",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
  EXPECT_EQ(d[0]["t6"], "1");
  EXPECT_EQ(d[0]["t7"], "1");
  EXPECT_EQ(d[0]["t8"], "1");
  EXPECT_EQ(d[0]["t9"], "1");
  EXPECT_EQ(d[0]["t10"], "1");
}

/*
 * collate version dpkg
 */
TEST_F(SQLTests, test_collate_version_dpkg_eq) {
  QueryData d;
  auto status = query(
      "select '1.0' = '1.0' collate version_dpkg as t0, \
              '1.0-0' = '1.0-0' collate version_dpkg as t1, \
              '1:2.0-10' = '1:2.0-10' collate version_dpkg as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
}

TEST_F(SQLTests, test_collate_version_dpkg_lt) {
  QueryData d;
  auto status = query(
      "select '1.0' < '1.1' collate version_dpkg as t0, \
              '22.07.5-2ubuntu1.3' < '22.07.5-2ubuntu1.4' collate version_dpkg as t1, \
              '12ubuntu4.2' < '12ubuntu4.3' collate version_dpkg as t2, \
              '2.38-4ubuntu2.1' < '2.38-4ubuntu2.2' collate version_dpkg as t3, \
              '1.19.2-2ubuntu0.1' < '1.19.2-2ubuntu0.2' collate version_dpkg as t4, \
              '2.5.13+dfsg-0ubuntu0.22.04.1' < '2.5.14+dfsg-0ubuntu0.22.04.2' collate version_dpkg as t5",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
}

TEST_F(SQLTests, test_collate_version_dpkg_gt) {
  QueryData d;
  auto status = query(
      "select '1.1' > '1.0' collate version_dpkg as t0, \
              '1.21.1ubuntu2.2' > '1.21.1ubuntu2.1' collate version_dpkg as t1, \
              '3.0.2-0ubuntu1.10' > '3.0.2-0ubuntu1.8' collate version_dpkg as t2, \
              '5.34.0-3ubuntu1.2' > '5.34.0-3ubuntu1.1' collate version_dpkg as t3, \
              '1.9.9-1ubuntu2.4' > '1.9.9-1ubuntu2.3' collate version_dpkg as t4, \
              '2:8.2.3995-1ubuntu2.9' > '2:8.2.3995-1ubuntu2.3' collate version_dpkg as t5",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
}

/*
 * collate version rhel
 */
TEST_F(SQLTests, test_collate_version_rhel_eq) {
  QueryData d;
  auto status = query(
      "select '1.0' = '1.0' collate version_rhel as t0, \
              '0.5.0~rc1^202' = '0.5.0~rc1^202' collate version_rhel as t1, \
              '1:1.0.0~rc2' = '1:1.0.0~rc2' collate version_rhel as t2",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
}

TEST_F(SQLTests, test_collate_version_rhel_lt) {
  QueryData d;
  auto status = query(
      "select '1.0' < '1.1' collate version_rhel as t0, \
              '1.0.0~rc2^2021' < '1.0.0' collate version_rhel as t1, \
              '1.0.0' < '1.0.1' collate version_rhel as t2, \
              '1.0.1' < '1.0.1^2021' collate version_rhel as t3, \
              '1.0.1^2021' < '1.0.1.security1' collate version_rhel as t4, \
              '1.0.1' < 'pkg-1.0.1.security1' collate version_rhel as t5, \
              '1.1.0~BETA2' < '1.1.0~CR1' collate version_rhel as t6, \
              '1.1.0.2021.SP1' < '1.1.0.2021.SP1_CP1' collate version_rhel as t7, \
              '9.11.4-26.P2.el7_9.10' < '32:9.11.4-26.P2.el7_9.13' collate version_rhel as t8, \
              '1:1.8.0.352.b08-2.el7_9' < '1:1.8.0.372.b07-1.el7_9' collate version_rhel as t9, \
              '5.6.0-1.linux' < '5.9.1-1.linux' collate version_rhel as t10",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
  EXPECT_EQ(d[0]["t6"], "1");
  EXPECT_EQ(d[0]["t7"], "1");
  EXPECT_EQ(d[0]["t8"], "1");
  EXPECT_EQ(d[0]["t9"], "1");
  EXPECT_EQ(d[0]["t10"], "1");
}

TEST_F(SQLTests, test_collate_version_rhel_gt) {
  QueryData d;
  auto status = query(
      "select '1.1' > '1.0' collate version_rhel as t0, \
              '1.0.0~rc2' > '1.0.0~rc1' collate version_rhel as t1, \
              '1.0.0' > '1.0.0~rc2' collate version_rhel as t2, \
              '1.0.1.security1' > '1.0.0~rc2' collate version_rhel as t3, \
              '1.1.0~BETA' > '1.0.1.security1' collate version_rhel as t4, \
              '1.1.0~CR1' > '1.1.0~BETA' collate version_rhel as t5, \
              '1.1.0.20201001.GA1' > '1.1.0~CR1' collate version_rhel as t6, \
              '1.0.0~rc2^20210101gf00fabd' > '1.0.0~rc2' collate version_rhel as t7, \
              '1.0.0' > '1.0.0~rc2^20210101gf00fabd' collate version_rhel as t8, \
              '1.0.1^20210203gbbbccc0' > '1.0.1' collate version_rhel as t9, \
              '1.0.1.security1' > '1.0.1^20210203gbbbccc0' collate version_rhel as t10",
      d);
  ASSERT_EQ(d.size(), 1U);
  EXPECT_EQ(d[0]["t0"], "1");
  EXPECT_EQ(d[0]["t1"], "1");
  EXPECT_EQ(d[0]["t2"], "1");
  EXPECT_EQ(d[0]["t3"], "1");
  EXPECT_EQ(d[0]["t4"], "1");
  EXPECT_EQ(d[0]["t5"], "1");
  EXPECT_EQ(d[0]["t6"], "1");
  EXPECT_EQ(d[0]["t7"], "1");
  EXPECT_EQ(d[0]["t8"], "1");
  EXPECT_EQ(d[0]["t9"], "1");
  EXPECT_EQ(d[0]["t10"], "1");
}

} // namespace osquery
