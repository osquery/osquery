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
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "../schema_stubs.h"
#include "osquery/tests/test_util.h"

namespace osquery {

class SchemaStubsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    // Read config content manually.
    readFile(kTestDataPath + "test_parse_schema_stubs.conf", content_);

    // Construct a config map, the typical output from `Config::genConfig`.
    config_data_["schema_stubs_test"] = content_;
    Config::get().reset();
  }

  void TearDown() override {
    Config::get().reset();
  }

 protected:
  std::string content_;
  std::map<std::string, std::string> config_data_;
};

//     "some_table": [ "text_column1", "int_column1/I", "text_column2/T",
//     "hidden_text_column1/Th", "indexed_int_column1/Ii" ]

TEST_F(SchemaStubsConfigParserPluginTests, test_table_query) {
  std::string query = "SELECT * FROM some_table";
  auto results = SQL(query);

  EXPECT_NE(0, results.getStatus().getCode()); // "no such table: some_table"

  Config::get().update(config_data_);

  results = SQL(query);

  EXPECT_EQ(0, results.getStatus().getCode());
  EXPECT_EQ(0, results.rows().size());
  EXPECT_EQ(4, results.columns().size()); // 1 is hidden

  results =
      SQL("SELECT text_column1, int_column1, text_column2, indexed_int_column1 "
          "FROM some_table WHERE int_column1 > 0");

  EXPECT_EQ(0, results.getStatus().getCode());
  EXPECT_EQ(0, results.rows().size());
}

TEST_F(SchemaStubsConfigParserPluginTests, table_names) {
  auto aliases = std::vector<std::string>();

  EXPECT_EQ("nemo/dd", SchemaStubsParseTableName("nemo/dd", aliases));
  EXPECT_EQ(0, aliases.size());

  // aliases same as table name
  EXPECT_EQ("nemo", SchemaStubsParseTableName("nemo|nemo", aliases));
  EXPECT_EQ(0, aliases.size());

  EXPECT_EQ("nemo", SchemaStubsParseTableName("nemo|omen", aliases));
  EXPECT_EQ(1, aliases.size());
  if (aliases.size() > 0) {
    EXPECT_EQ("omen", aliases[0]);
  }
  aliases.clear();

  EXPECT_EQ("a", SchemaStubsParseTableName("a|one||two|three|four", aliases));
  EXPECT_EQ(4, aliases.size());
  if (aliases.size() == 4) {
    EXPECT_EQ("one", aliases[0]);
    EXPECT_EQ("four", aliases[3]);
  }
  aliases.clear();
}

TEST_F(SchemaStubsConfigParserPluginTests, column_names) {
  ColumnType columnType = TEXT_TYPE;
  ColumnOptions opts = ColumnOptions::DEFAULT;

  EXPECT_EQ("column_name",
            SchemaStubsParseColumnName("column_name////Z", columnType, opts));
  EXPECT_EQ(TEXT_TYPE, columnType);
  EXPECT_EQ(ColumnOptions::DEFAULT, opts);

  EXPECT_EQ("c", SchemaStubsParseColumnName("c", columnType, opts));
  EXPECT_EQ(TEXT_TYPE, columnType);
  EXPECT_EQ(ColumnOptions::DEFAULT, opts);

  EXPECT_EQ("", SchemaStubsParseColumnName("/", columnType, opts));
  EXPECT_EQ(TEXT_TYPE, columnType);
  EXPECT_EQ(ColumnOptions::DEFAULT, opts);
}

TEST_F(SchemaStubsConfigParserPluginTests, types_and_options) {
  ColumnType columnType = TEXT_TYPE;
  ColumnOptions opts = ColumnOptions::DEFAULT;

  SchemaStubsParseTypeAndOptions("", columnType, opts);

  EXPECT_EQ(TEXT_TYPE, columnType);
  EXPECT_EQ(ColumnOptions::DEFAULT, opts);

  SchemaStubsParseTypeAndOptions("zkjltBILUT.;?", columnType, opts);

  EXPECT_EQ(TEXT_TYPE, columnType);
  EXPECT_EQ(ColumnOptions::DEFAULT, opts);

  SchemaStubsParseTypeAndOptions("Uahir", columnType, opts);

  EXPECT_EQ(UNSIGNED_BIGINT_TYPE, columnType);
  int val = (int)opts;
  EXPECT_TRUE((val & (int)ColumnOptions::ADDITIONAL));
  EXPECT_TRUE((val & (int)ColumnOptions::HIDDEN));
  EXPECT_TRUE((val & (int)ColumnOptions::INDEX));
  EXPECT_TRUE((val & (int)ColumnOptions::REQUIRED));

  SchemaStubsParseTypeAndOptions("I", columnType, opts);
  
  EXPECT_EQ(INTEGER_TYPE, columnType);

  SchemaStubsParseTypeAndOptions("B", columnType, opts);
  
  EXPECT_EQ(BLOB_TYPE, columnType);

  SchemaStubsParseTypeAndOptions("L", columnType, opts);
  
  EXPECT_EQ(BIGINT_TYPE, columnType);

  SchemaStubsParseTypeAndOptions("D", columnType, opts);
  
  EXPECT_EQ(DOUBLE_TYPE, columnType);
}

} // namespace osquery
