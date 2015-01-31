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
#include <osquery/registry.h>

#include "osquery/core/virtual_table.h"

namespace osquery {
namespace tables {

class VirtualTableTests : public testing::Test {};

// sample plugin used on tests
class sampleTablePlugin : public TablePlugin {
 private:
  TableColumns columns() {
    return {
        {"foo", "INTEGER"}, {"bar", "TEXT"},
    };
  }
};

TEST_F(VirtualTableTests, test_tableplugin_columndefinition) {
  auto table = sampleTablePlugin();
  EXPECT_EQ("(foo INTEGER, bar TEXT)", table.columnDefinition());
}

TEST_F(VirtualTableTests, test_tableplugin_statement) {
  auto table = sampleTablePlugin();
  table.setName("sample");
  EXPECT_EQ("CREATE TABLE sample(foo INTEGER, bar TEXT)", table.statement());
}

TEST_F(VirtualTableTests, test_sqlite3_attach_vtable) {
  auto table = sampleTablePlugin();
  table.setName("sample");
  sqlite3* db = nullptr;
  sqlite3_open(":memory:", &db);

  // Virtual tables require the registry/plugin API to query tables.
  int rc = osquery::tables::attachTable(db, "failed_sample");
  EXPECT_EQ(rc, SQLITE_ERROR);

  // The table attach will complete only when the table name is registered.
  NewRegistry::add<sampleTablePlugin>("table", "sample");
  rc = osquery::tables::attachTable(db, "sample");
  EXPECT_EQ(rc, SQLITE_OK);

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
