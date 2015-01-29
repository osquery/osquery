/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include "osquery/core/virtual_table.h"

namespace osquery {
namespace tables {

class VirtualTableTests : public testing::Test {};

// sample plugin used on tests
class sampleTablePlugin : public TablePlugin {
 public:
  TableName name = "sample";
  TableColumns columns = {std::make_pair("foo", "INTEGER"),
                          std::make_pair("bar", "TEXT")};

  QueryData generate(QueryContext& request) {
    // do nothing (not used), just to fullfil interface
    QueryData results;
    return results;
  }

 public:
  sampleTablePlugin() {}
  int attachVtable(sqlite3* db) {
    return sqlite3_attach_vtable<sampleTablePlugin>(db, name, columns);
  }
  virtual ~sampleTablePlugin() {}
};

TEST_F(VirtualTableTests, test_tableplugin_columndefinition) {
  auto table = sampleTablePlugin();
  EXPECT_EQ("(foo INTEGER, bar TEXT)",
            TablePlugin::columnDefinition(table.columns));
}

TEST_F(VirtualTableTests, test_tableplugin_statement) {
  auto table = sampleTablePlugin();
  EXPECT_EQ("CREATE TABLE sample(foo INTEGER, bar TEXT)",
            table.statement(table.name, table.columns));
}

TEST_F(VirtualTableTests, test_sqlite3_attach_vtable) {
  auto table = sampleTablePlugin();
  sqlite3* db = nullptr;
  sqlite3_open(":memory:", &db);
  table.attachVtable(db);
  std::string q = "SELECT sql FROM sqlite_temp_master WHERE tbl_name='sample';";
  int error_return;
  QueryData results = query(q, error_return, db);
  EXPECT_EQ("CREATE VIRTUAL TABLE sample USING sample(foo INTEGER, bar TEXT)",
            results[0]["sql"]);
  sqlite3_close(db);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
