/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <benchmark/benchmark.h>

#include <osquery/core.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/sql/virtual_table.h"

namespace osquery {

class BenchmarkTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {{"test_int", "INTEGER"}, {"test_text", "TEXT"}};
  }

  QueryData generate(QueryContext& ctx) {
    QueryData results;
    results.push_back({{"test_int", "0"}});
    results.push_back({{"test_int", "0"}, {"test_text", "hello"}});
    return results;
  }
};

static void SQL_virtual_table_registry(benchmark::State& state) {
  // Add a sample virtual table plugin.
  // Profile calling the plugin's column data.
  Registry::add<BenchmarkTablePlugin>("table", "benchmark");
  while (state.KeepRunning()) {
    PluginResponse res;
    Registry::call("table", "benchmark", {{"action", "generate"}}, res);
  }
}

BENCHMARK(SQL_virtual_table_registry);

static void SQL_virtual_table_internal(benchmark::State& state) {
  Registry::add<BenchmarkTablePlugin>("table", "benchmark");
  PluginResponse res;
  Registry::call("table", "benchmark", {{"action", "columns"}}, res);

  // Attach a sample virtual table.
  auto dbc = SQLiteDBManager::get();
  attachTableInternal("benchmark", columnDefinition(res), dbc.db());

  while (state.KeepRunning()) {
    QueryData results;
    queryInternal("select * from benchmark", results, dbc.db());
  }
}

BENCHMARK(SQL_virtual_table_internal);

class BenchmarkLongTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {{"test_int", "INTEGER"}, {"test_text", "TEXT"}};
  }

  QueryData generate(QueryContext& ctx) {
    QueryData results;
    for (int i = 0; i < 1000; i++) {
      results.push_back({{"test_int", "0"}, {"test_text", "hello"}});
    }
    return results;
  }
};

static void SQL_virtual_table_internal_long(benchmark::State& state) {
  Registry::add<BenchmarkLongTablePlugin>("table", "long_benchmark");
  PluginResponse res;
  Registry::call("table", "long_benchmark", {{"action", "columns"}}, res);

  // Attach a sample virtual table.
  auto dbc = SQLiteDBManager::get();
  attachTableInternal("long_benchmark", columnDefinition(res), dbc.db());

  while (state.KeepRunning()) {
    QueryData results;
    queryInternal("select * from long_benchmark", results, dbc.db());
  }
}

BENCHMARK(SQL_virtual_table_internal_long);

static void SQL_select_metadata(benchmark::State& state) {
  auto dbc = SQLiteDBManager::get();
  while (state.KeepRunning()) {
    QueryData results;
    queryInternal(
        "select count(*) from sqlite_temp_master;", results, dbc.db());
  }
}

BENCHMARK(SQL_select_metadata);

static void SQL_select_basic(benchmark::State& state) {
  // Profile executing a query against an internal, already attached table.
  while (state.KeepRunning()) {
    auto results = SQLInternal("select * from benchmark");
  }
}

BENCHMARK(SQL_select_basic);
}
