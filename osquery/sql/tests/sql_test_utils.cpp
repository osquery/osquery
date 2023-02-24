/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/tests/sql_test_utils.h>

namespace osquery {

DECLARE_bool(logger_numerics);

QueryDataTyped getTestDBExpectedResults() {
  QueryDataTyped d;
  RowTyped row1;
  row1["username"] = "mike";
  row1["age"] = 23LL;
  d.push_back(row1);
  RowTyped row2;
  row2["username"] = "matt";
  row2["age"] = 24LL;
  d.push_back(row2);
  return d;
}

std::vector<std::pair<std::string, QueryDataTyped>> getTestDBResultStream() {
  std::vector<std::pair<std::string, QueryDataTyped>> results;

  std::string q2 =
      R"(INSERT INTO test_table (username, age) VALUES ("joe", 25))";
  QueryDataTyped d2;
  RowTyped row2_1;
  row2_1["username"] = "mike";
  row2_1["age"] = 23LL;
  d2.push_back(row2_1);
  RowTyped row2_2;
  row2_2["username"] = "matt";
  row2_2["age"] = 24LL;
  d2.push_back(row2_2);
  RowTyped row2_3;
  row2_3["username"] = "joe";
  row2_3["age"] = 25LL;
  d2.push_back(row2_3);
  results.push_back(std::make_pair(q2, d2));

  std::string q3 = R"(UPDATE test_table SET age = 27 WHERE username = "matt")";
  QueryDataTyped d3;
  RowTyped row3_1;
  row3_1["username"] = "mike";
  row3_1["age"] = 23LL;
  d3.push_back(row3_1);
  RowTyped row3_2;
  row3_2["username"] = "matt";
  row3_2["age"] = 27LL;
  d3.push_back(row3_2);
  RowTyped row3_3;
  row3_3["username"] = "joe";
  row3_3["age"] = 25LL;
  d3.push_back(row3_3);
  results.push_back(std::make_pair(q3, d3));

  std::string q4 =
      R"(DELETE FROM test_table WHERE username = "matt" AND age = 27)";
  QueryDataTyped d4;
  RowTyped row4_1;
  row4_1["username"] = "mike";
  row4_1["age"] = 23LL;
  d4.push_back(row4_1);
  RowTyped row4_2;
  row4_2["username"] = "joe";
  row4_2["age"] = 25LL;
  d4.push_back(row4_2);
  results.push_back(std::make_pair(q4, d4));

  return results;
}

ColumnNames getSerializedRowColumnNames(bool unordered_and_repeated) {
  ColumnNames cn;
  if (unordered_and_repeated) {
    cn.push_back("repeated_column");
  }
  cn.push_back("alphabetical");
  cn.push_back("foo");
  cn.push_back("meaning_of_life");
  cn.push_back("repeated_column");
  return cn;
}

std::pair<JSON, RowTyped> getSerializedRow(bool unordered_and_repeated) {
  auto cns = getSerializedRowColumnNames(unordered_and_repeated);

  RowTyped r;
  auto doc = JSON::newObject();
  for (const auto& cn : cns) {
    auto c_value = cn + "_value";
    r[cn] = c_value;
    doc.addCopy(cn, c_value);
  }
  return std::make_pair(std::move(doc), r);
}

std::pair<JSON, QueryDataTyped> getSerializedQueryData() {
  auto r = getSerializedRow(false);
  QueryDataTyped q = {r.second, r.second};

  JSON doc = JSON::newArray();
  auto arr1 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr1);
  doc.push(arr1);

  auto arr2 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr2);
  doc.push(arr2);

  return std::make_pair(std::move(doc), q);
}

std::pair<std::string, QueryDataTyped> getSerializedQueryDataJSON() {
  auto results = getSerializedQueryData();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, results.second);
}

std::pair<JSON, DiffResults> getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  JSON doc = JSON::newObject();
  doc.add("removed", qd.first.doc());
  doc.add("added", qd.first.doc());

  return std::make_pair(std::move(doc), std::move(diff_results));
}

std::pair<JSON, QueryLogItem> getSerializedQueryLogItem() {
  std::pair<JSON, QueryLogItem> p;
  QueryLogItem i;
  JSON doc = JSON::newObject();
  auto dr = getSerializedDiffResults();
  i.isSnapshot = false;
  i.results = std::move(dr.second);
  i.name = "foobar";
  i.calendar_time = "Mon Aug 25 12:10:57 2014";
  i.time = 1408993857;
  i.identifier = "foobaz";
  i.epoch = 0LL;
  i.counter = 0LL;

  auto diff_doc = doc.getObject();
  diff_doc.Swap(dr.first.doc());
  doc.add("diffResults", diff_doc);
  doc.addRef("name", "foobar");
  doc.addRef("hostIdentifier", "foobaz");
  doc.addRef("calendarTime", "Mon Aug 25 12:10:57 2014");
  doc.add("unixTime", 1408993857);
  doc.add("epoch", std::size_t{0});
  doc.add("counter", std::size_t{0});
  doc.add("numerics", FLAGS_logger_numerics);

  return std::make_pair(std::move(doc), std::move(i));
}

std::pair<JSON, QueryDataTyped> getSerializedQueryDataWithColumnOrder() {
  auto r = getSerializedRow(true);
  QueryDataTyped q = {r.second, r.second};
  JSON doc = JSON::newArray();
  auto arr1 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr1);
  doc.push(arr1);

  auto arr2 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr2);
  doc.push(arr2);

  return std::make_pair(std::move(doc), q);
}

std::pair<std::string, DiffResults> getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, std::move(results.second));
}

std::pair<std::string, QueryLogItem> getSerializedQueryLogItemJSON() {
  auto results = getSerializedQueryLogItem();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, std::move(results.second));
}

} // namespace osquery
