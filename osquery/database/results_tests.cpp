/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/database/results.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

class ResultsTests : public testing::Test {};
std::string escapeNonPrintableBytes(const std::string& data);

TEST_F(ResultsTests, test_simple_diff) {
  QueryData o;
  QueryData n;

  Row r1;
  r1["foo"] = "bar";
  n.push_back(r1);

  auto results = diff(o, n);
  EXPECT_EQ(results.added, n);
  EXPECT_EQ(results.removed, o);
}

TEST_F(ResultsTests, test_serialize_row) {
  auto results = getSerializedRow();
  pt::ptree tree;
  auto s = serializeRow(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_query_data) {
  auto results = getSerializedQueryData();
  pt::ptree tree;
  auto s = serializeQueryData(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_diff_results) {
  auto results = getSerializedDiffResults();
  pt::ptree tree;
  auto s = serializeDiffResults(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_diff_results_json) {
  auto results = getSerializedDiffResultsJSON();
  std::string json;
  auto s = serializeDiffResultsJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_serialize_historical_query_results) {
  auto results = getSerializedHistoricalQueryResults();
  pt::ptree tree;
  auto s = serializeHistoricalQueryResults(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_historical_query_results_json) {
  auto results = getSerializedHistoricalQueryResultsJSON();
  std::string json;
  auto s = serializeHistoricalQueryResultsJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_deserialize_historical_query_results) {
  auto results = getSerializedHistoricalQueryResults();
  HistoricalQueryResults r;
  auto s = deserializeHistoricalQueryResults(results.first, r);
  EXPECT_EQ(results.second, r);
  EXPECT_EQ(results.second.mostRecentResults, r.mostRecentResults);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(ResultsTests, test_deserialize_historical_query_results_json) {
  auto results = getSerializedHistoricalQueryResultsJSON();
  HistoricalQueryResults r;
  auto s = deserializeHistoricalQueryResultsJSON(results.first, r);
  EXPECT_EQ(results.second, r);
  EXPECT_EQ(results.second.mostRecentResults, r.mostRecentResults);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(ResultsTests, test_serialize_scheduled_query_log_item) {
  auto results = getSerializedScheduledQueryLogItem();
  pt::ptree tree;
  auto s = serializeScheduledQueryLogItem(results.second, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, tree);
}

TEST_F(ResultsTests, test_serialize_scheduled_query_log_item_json) {
  auto results = getSerializedScheduledQueryLogItemJSON();
  std::string json;
  auto s = serializeScheduledQueryLogItemJSON(results.second, json);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(results.first, json);
}

TEST_F(ResultsTests, test_unicode_to_ascii_conversion) {
  EXPECT_EQ(escapeNonPrintableBytes("しかたがない"),
            "\\xE3\\x81\\x97\\xE3\\x81\\x8B\\xE3\\x81\\x9F\\xE3\\x81\\x8C\\xE3"
            "\\x81\\xAA\\xE3\\x81\\x84");
  EXPECT_EQ(escapeNonPrintableBytes("悪因悪果"),
            "\\xE6\\x82\\xAA\\xE5\\x9B\\xA0\\xE6\\x82\\xAA\\xE6\\x9E\\x9C");
  EXPECT_EQ(escapeNonPrintableBytes("モンスターハンター"),
            "\\xE3\\x83\\xA2\\xE3\\x83\\xB3\\xE3\\x82\\xB9\\xE3\\x82\\xBF\\xE3"
            "\\x83\\xBC\\xE3\\x83\\x8F\\xE3\\x83\\xB3\\xE3\\x82\\xBF\\xE3\\x83"
            "\\xBC");
  EXPECT_EQ(
      escapeNonPrintableBytes(
          "съешь же ещё этих мягких французских булок, да выпей чаю"),
      "\\xD1\\x81\\xD1\\x8A\\xD0\\xB5\\xD1\\x88\\xD1\\x8C \\xD0\\xB6\\xD0\\xB5 "
      "\\xD0\\xB5\\xD1\\x89\\xD1\\x91 \\xD1\\x8D\\xD1\\x82\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xBC\\xD1\\x8F\\xD0\\xB3\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD1\\x84\\xD1\\x80\\xD0\\xB0\\xD0\\xBD\\xD1\\x86\\xD1\\x83\\xD0\\xB7\\"
      "xD1\\x81\\xD0\\xBA\\xD0\\xB8\\xD1\\x85 "
      "\\xD0\\xB1\\xD1\\x83\\xD0\\xBB\\xD0\\xBE\\xD0\\xBA, "
      "\\xD0\\xB4\\xD0\\xB0 \\xD0\\xB2\\xD1\\x8B\\xD0\\xBF\\xD0\\xB5\\xD0\\xB9 "
      "\\xD1\\x87\\xD0\\xB0\\xD1\\x8E");

  EXPECT_EQ(
      escapeNonPrintableBytes("The quick brown fox jumps over the lazy dog."),
      "The quick brown fox jumps over the lazy dog.");
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
  EXPECT_EQ(q.size(), 1);

  s = addUniqueRowToQueryData(q, r2);
  EXPECT_TRUE(s);
  EXPECT_EQ(q.size(), 2);

  s = addUniqueRowToQueryData(q, r3);
  EXPECT_FALSE(s);
  EXPECT_EQ(q.size(), 2);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
