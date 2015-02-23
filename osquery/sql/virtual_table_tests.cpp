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
#include <osquery/sql.h>

#include "osquery/sql/virtual_table.h"

namespace osquery {
namespace tables {

class VirtualTableTests : public testing::Test {};

// sample plugin used on tests
class sampleTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        {"foo", "INTEGER"}, {"bar", "TEXT"},
    };
  }
};

TEST_F(VirtualTableTests, test_tableplugin_columndefinition) {
  auto table = std::make_shared<sampleTablePlugin>();
  EXPECT_EQ("(foo INTEGER, bar TEXT)", table->columnDefinition());
}

TEST_F(VirtualTableTests, test_sqlite3_attach_vtable) {
  auto table = std::make_shared<sampleTablePlugin>();
  table->setName("sample");
  //sqlite3* db = nullptr;
  //sqlite3_open(":memory:", &db);
  auto dbc = SQLiteDBManager::get();

  // Virtual tables require the registry/plugin API to query tables.
  auto status =
      tables::attachTableInternal("failed_sample", "(foo INTEGER)", dbc.db());
  EXPECT_EQ(status.getCode(), SQLITE_ERROR);

  // The table attach will complete only when the table name is registered.
  Registry::add<sampleTablePlugin>("table", "sample");
  PluginResponse response;
  status = Registry::call("table", "sample", {{"action", "columns"}}, response);
  EXPECT_TRUE(status.ok());

  // Use the table name, plugin-generated schema to attach.
  status = tables::attachTableInternal(
      "sample", tables::columnDefinition(response), dbc.db());
  EXPECT_EQ(status.getCode(), SQLITE_OK);

  std::string q = "SELECT sql FROM sqlite_temp_master WHERE tbl_name='sample';";
  QueryData results;
  status = queryInternal(q, results, dbc.db());
  EXPECT_EQ("CREATE VIRTUAL TABLE sample USING sample(foo INTEGER, bar TEXT)",
            results[0]["sql"]);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
