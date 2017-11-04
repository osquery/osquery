/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

class ResultsTests : public testing::Test {};

TEST_F(ResultsTests, test_simple_diff) {
  QueryDataSet os;
  QueryData o;
  QueryData n;

  Row r1;
  r1["foo"] = "bar";
  n.push_back(r1);

  auto results = diff(os, n);
  EXPECT_EQ(results.added, n);
  EXPECT_EQ(results.removed, o);
}

TEST_F(ResultsTests, test_serialize_row) {
  auto results = getSerializedRow();
  auto doc = JSON::newObject();
  auto s = serializeRow(results.second, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(doc.doc()["meaning_of_life"], "meaning_of_life_value");
  EXPECT_EQ(doc.doc()["alphabetical"], "alphabetical_value");
}

TEST_F(ResultsTests, test_deserialize_row_json) {
  auto results = getSerializedRow();
  std::string input;
  serializeRowJSON(results.second, input);

  // Pull the serialized JSON back into a Row output container.
  Row output;
  auto s = deserializeRowJSON(input, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input row.
  EXPECT_EQ(output, results.second);
}

TEST_F(ResultsTests, test_serialize_query_data) {
  auto results = getSerializedQueryData();
  //  pt::ptree tree;

  auto doc = JSON::newArray();
  auto s = serializeQueryData(results.second, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first.doc(), doc.doc());
}

TEST_F(ResultsTests, test_serialize_query_data_in_column_order) {
  auto results = getSerializedQueryDataWithColumnOrder();
  auto column_names = getSerializedRowColumnNames(true);
  //  pt::ptree tree;

  auto doc = JSON::newArray();
  auto s = serializeQueryData(results.second, column_names, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first.doc(), doc.doc());
}

TEST_F(ResultsTests, test_serialize_query_data_json) {
  auto results = getSerializedQueryDataJSON();
  std::string json;
  auto s = serializeQueryDataJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_query_data_json) {
  auto results = getSerializedQueryDataJSON();

  // Pull the serialized JSON back into a QueryData output container.
  QueryData output;
  auto s = deserializeQueryDataJSON(results.first, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input query data.
  EXPECT_EQ(output, results.second);
}

TEST_F(ResultsTests, test_serialize_diff_results) {
  auto results = getSerializedDiffResults();
  // pt::ptree tree;
  auto doc = JSON::newObject();
  auto s = serializeDiffResults(results.second, doc, doc.doc());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first.doc(), doc.doc());
}

TEST_F(ResultsTests, test_serialize_diff_results_json) {
  auto results = getSerializedDiffResultsJSON();
  std::string json;
  auto s = serializeDiffResultsJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_serialize_query_log_item) {
  auto results = getSerializedQueryLogItem();
  //  pt::ptree tree;
  auto doc = JSON::newObject();
  auto s = serializeQueryLogItem(results.second, doc);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first.doc(), doc.doc());
}

TEST_F(ResultsTests, test_serialize_query_log_item_json) {
  auto results = getSerializedQueryLogItemJSON();
  std::string json;
  auto s = serializeQueryLogItemJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_query_log_item_json) {
  auto results = getSerializedQueryLogItemJSON();

  // Pull the serialized JSON back into a QueryLogItem output container.
  QueryLogItem output;
  auto s = deserializeQueryLogItemJSON(results.first, output);
  EXPECT_TRUE(s.ok());
  // The output container should match the input query data.
  EXPECT_EQ(output, results.second);
}

TEST_F(ResultsTests, test_adding_duplicate_rows_to_query_data) {
  Row r1, r2, r3;
  r1["foo"] = "bar";
  r1["baz"] = "boo";

  r2["foo"] = "baz";
  r2["baz"] = "bop";

  r3["foo"] = "baz";
  r3["baz"] = "bop";

  QueryData q;
  bool s;

  s = addUniqueRowToQueryData(q, r1);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 1U);

  s = addUniqueRowToQueryData(q, r2);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 2U);

  s = addUniqueRowToQueryData(q, r3);
  EXPECT_FALSE(s);
  EXPECT_EQ(q.size(), 2U);
}
}
