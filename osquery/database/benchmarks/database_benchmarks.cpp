/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <benchmark/benchmark.h>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/query.h>

#include "osquery/core/json.h"
#include "osquery/tests/test_util.h"

namespace osquery {

QueryData getExampleQueryData(size_t x, size_t y) {
  QueryData qd;
  Row r;

  // Fill in a row with x;
  for (size_t i = 0; i < x; i++) {
    r["key" + std::to_string(i)] = std::to_string(i) + "content";
  }
  // Fill in the vector with y;
  for (size_t i = 0; i < y; i++) {
    qd.push_back(r);
  }
  return qd;
}

QueryDataSet getExampleQueryDataSet(size_t x, size_t y) {
  QueryDataSet qds;
  Row r;

  // Fill in a row with x;
  for (size_t i = 0; i < x; i++) {
    r["key" + std::to_string(i)] = std::to_string(i) + "content";
  }
  // Fill in the vector with y;
  for (size_t i = 0; i < y; i++) {
    qds.insert(r);
  }
  return qds;
}

ColumnNames getExampleColumnNames(size_t x) {
  ColumnNames cn;
  for (size_t i = 0; i < x; i++) {
    cn.push_back("key" + std::to_string(i));
  }
  return cn;
}

static void DATABASE_serialize(benchmark::State& state) {
  auto qd = getExampleQueryData(state.range_x(), state.range_y());
  while (state.KeepRunning()) {
    auto doc = JSON::newArray();
    serializeQueryData(qd, doc, doc.doc());
  }
}

BENCHMARK(DATABASE_serialize)->ArgPair(1, 1)->ArgPair(10, 10)->ArgPair(10, 100);

static void DATABASE_serialize_column_order(benchmark::State& state) {
  auto qd = getExampleQueryData(state.range_x(), state.range_y());
  auto cn = getExampleColumnNames(state.range_x());
  while (state.KeepRunning()) {
    auto doc = JSON::newArray();
    serializeQueryData(qd, cn, doc, doc.doc());
  }
}

BENCHMARK(DATABASE_serialize_column_order)
    ->ArgPair(1, 1)
    ->ArgPair(10, 10)
    ->ArgPair(10, 100)
    ->ArgPair(100, 100);

static void DATABASE_serialize_json(benchmark::State& state) {
  auto qd = getExampleQueryData(state.range_x(), state.range_y());
  while (state.KeepRunning()) {
    std::string content;
    serializeQueryDataJSON(qd, content);
  }
}

BENCHMARK(DATABASE_serialize_json)
    ->ArgPair(1, 1)
    ->ArgPair(10, 10)
    ->ArgPair(10, 100);

static void DATABASE_diff(benchmark::State& state) {
  QueryData qd = getExampleQueryData(state.range_x(), state.range_y());
  QueryDataSet qds = getExampleQueryDataSet(state.range_x(), state.range_y());
  while (state.KeepRunning()) {
    auto d = diff(qds, qd);
  }
}

BENCHMARK(DATABASE_diff)->ArgPair(1, 1)->ArgPair(10, 10)->ArgPair(10, 100);

static void DATABASE_query_results(benchmark::State& state) {
  auto qd = getExampleQueryData(state.range_x(), state.range_y());
  auto query = getOsqueryScheduledQuery();
  while (state.KeepRunning()) {
    DiffResults diff_results;
    uint64_t counter;
    auto dbq = Query("default", query);
    dbq.addNewResults(std::move(qd), 0, counter, diff_results);
  }
}

BENCHMARK(DATABASE_query_results)
    ->ArgPair(1, 1)
    ->ArgPair(10, 10)
    ->ArgPair(10, 100);

static void DATABASE_get(benchmark::State& state) {
  setDatabaseValue(kPersistentSettings, "benchmark", "1");
  while (state.KeepRunning()) {
    std::string value;
    getDatabaseValue(kPersistentSettings, "benchmark", value);
  }
  // All benchmarks will share a single database handle.
  deleteDatabaseValue(kPersistentSettings, "benchmark");
}

BENCHMARK(DATABASE_get);

static void DATABASE_store(benchmark::State& state) {
  while (state.KeepRunning()) {
    setDatabaseValue(kPersistentSettings, "benchmark", "1");
  }
  // All benchmarks will share a single database handle.
  deleteDatabaseValue(kPersistentSettings, "benchmark");
}

BENCHMARK(DATABASE_store);

static void DATABASE_store_large(benchmark::State& state) {
  // Serialize the example result set into a string.
  std::string content;
  auto qd = getExampleQueryData(20, 100);
  serializeQueryDataJSON(qd, content);

  while (state.KeepRunning()) {
    setDatabaseValue(kPersistentSettings, "benchmark", content);
  }
  // All benchmarks will share a single database handle.
  deleteDatabaseValue(kPersistentSettings, "benchmark");
}

BENCHMARK(DATABASE_store_large);

static void DATABASE_store_append(benchmark::State& state) {
  // Serialize the example result set into a string.
  std::string content;
  auto qd = getExampleQueryData(20, 100);
  serializeQueryDataJSON(qd, content);

  size_t k = 0;
  while (state.KeepRunning()) {
    setDatabaseValue(kPersistentSettings, "key" + std::to_string(k), content);
    deleteDatabaseValue(kPersistentSettings, "key" + std::to_string(k));
    k++;
  }

  // All benchmarks will share a single database handle.
  for (size_t i = 0; i < k; ++i) {
    deleteDatabaseValue(kPersistentSettings, "key" + std::to_string(i));
  }
}

BENCHMARK(DATABASE_store_append);
}
