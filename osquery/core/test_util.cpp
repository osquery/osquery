// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core/test_util.h"

#include <deque>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

#include "osquery/core/sqlite_util.h"

using namespace osquery::db;
namespace pt = boost::property_tree;

namespace osquery { namespace core {

const std::string kTestQuery = "SELECT * FROM test_table";

sqlite3* createTestDB() {
  sqlite3* db = createDB();
  char *err = nullptr;
  std::vector<std::string> queries = {
    "CREATE TABLE test_table ("
      "username varchar(30) primary key, "
      "age int"
     ")",
    "INSERT INTO test_table VALUES (\"mike\", 23)",
    "INSERT INTO test_table VALUES (\"matt\", 24)"
  };
  for (auto q : queries) {
    sqlite3_exec(db, q.c_str(), nullptr, nullptr, &err);
    if (err != nullptr) {
      LOG(ERROR) << "Error creating test database: " << err;
      return nullptr;
    }
  }

  return db;
}

QueryData getTestDBExpectedResults() {
  QueryData d;
  Row row1;
  row1["username"] = "mike";
  row1["age"] = "23";
  d.push_back(row1);
  Row row2;
  row2["username"] = "matt";
  row2["age"] = "24";
  d.push_back(row2);
  return d;
}

std::vector<std::pair<std::string, QueryData>> getTestDBResultStream() {
  std::vector<std::pair<std::string, QueryData>> results;

  std::string q2 =
    "INSERT INTO test_table (username, age) VALUES (\"joe\", 25)";
  QueryData d2;
  Row row2_1;
  row2_1["username"] = "mike";
  row2_1["age"] = "23";
  d2.push_back(row2_1);
  Row row2_2;
  row2_2["username"] = "matt";
  row2_2["age"] = "24";
  d2.push_back(row2_2);
  Row row2_3;
  row2_3["username"] = "joe";
  row2_3["age"] = "25";
  d2.push_back(row2_3);
  results.push_back(std::make_pair(q2, d2));

  std::string q3 = "UPDATE test_table SET age = 27 WHERE username = \"matt\"";
  QueryData d3;
  Row row3_1;
  row3_1["username"] = "mike";
  row3_1["age"] = "23";
  d3.push_back(row3_1);
  Row row3_2;
  row3_2["username"] = "matt";
  row3_2["age"] = "27";
  d3.push_back(row3_2);
  Row row3_3;
  row3_3["username"] = "joe";
  row3_3["age"] = "25";
  d3.push_back(row3_3);
  results.push_back(std::make_pair(q3, d3));

  std::string q4 =
    "DELETE FROM test_table WHERE username = \"matt\" AND age = 27";
  QueryData d4;
  Row row4_1;
  row4_1["username"] = "mike";
  row4_1["age"] = "23";
  d4.push_back(row4_1);
  Row row4_2;
  row4_2["username"] = "joe";
  row4_2["age"] = "25";
  d4.push_back(row4_2);
  results.push_back(std::make_pair(q4, d4));

  return results;
}

osquery::config::OsqueryScheduledQuery getOsqueryScheduledQuery() {
  osquery::config::OsqueryScheduledQuery q;
  q.name = "foobartest";
  q.query = "SELECT filename FROM fs WHERE path = '/bin' ORDER BY filename";
  q.interval = 5;
  return q;
}

std::pair<boost::property_tree::ptree, Row> getSerializedRow() {
  Row r;
  r["foo"] = "bar";
  r["meaning_of_life"] = "42";
  pt::ptree arr;
  arr.put<std::string>("foo", "bar");
  arr.put<std::string>("meaning_of_life", "42");
  return std::make_pair(arr, r);
}

std::pair<boost::property_tree::ptree, QueryData> getSerializedQueryData() {
  auto r = getSerializedRow();
  QueryData q = {r.second, r.second};
  pt::ptree arr;
  arr.push_back(std::make_pair("", r.first));
  arr.push_back(std::make_pair("", r.first));
  return std::make_pair(arr, q);
}

std::pair<boost::property_tree::ptree, DiffResults>
getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  pt::ptree root;
  root.add_child("added", qd.first);
  root.add_child("removed", qd.first);

  return std::make_pair(root, diff_results);
}

std::pair<std::string, osquery::db::DiffResults>
getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<pt::ptree, osquery::db::HistoricalQueryResults>
getSerializedHistoricalQueryResults() {
  auto qd = getSerializedQueryData();
  auto dr = getSerializedDiffResults();
  HistoricalQueryResults r;
  r.executions = std::deque<int>{2,1};
  r.mostRecentResults.first = 2;
  r.mostRecentResults.second = qd.second;
  r.pastResults[1] = dr.second;

  pt::ptree root;

  pt::ptree executions;
  pt::ptree item1;
  item1.put("", 2);
  executions.push_back(std::make_pair("", item1));
  pt::ptree item2;
  item2.put("", 1);
  executions.push_back(std::make_pair("", item2));
  root.add_child("executions", executions);

  pt::ptree mostRecentResults;
  mostRecentResults.add_child("2", qd.first);
  root.add_child("mostRecentResults", mostRecentResults);

  pt::ptree pastResults;
  pastResults.add_child("1", dr.first);
  root.add_child("pastResults", pastResults);

  return std::make_pair(root, r);
}

std::pair<std::string, osquery::db::HistoricalQueryResults>
getSerializedHistoricalQueryResultsJSON() {
  auto results = getSerializedHistoricalQueryResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<boost::property_tree::ptree, osquery::db::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItem() {
  ScheduledQueryLogItem i;
  pt::ptree root;
  auto dr = getSerializedDiffResults();
  i.diffResults = dr.second;
  i.name = "foobar";
  root.add_child("diffResults", dr.first);
  root.put<std::string>("name", "foobar");
  return std::make_pair(root, i);
}

std::pair<std::string, osquery::db::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItemJSON() {
  auto results = getSerializedScheduledQueryLogItem();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::string getEtcHostsContent() {
  std::string content =
    "##\n"
    "# Host Database\n"
    "#\n"
    "# localhost is used to configure the loopback interface\n"
    "# when the system is booting.  Do not change this entry.\n"
    "##\n"
    "127.0.0.1       localhost\n"
    "255.255.255.255 broadcasthost\n"
    "::1             localhost\n"
    "fe80::1%lo0     localhost\n";
  return content;
}

osquery::db::QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;

  row1["127.0.0.1"] = "localhost";
  row2["255.255.255.255"] = "broadcasthost";
  row3["::1"] = "localhost";
  row4["fe80::1%lo0"] = "localhost";
  return {row1, row2, row3, row4};
}

}}
