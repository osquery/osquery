// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core/test_util.h"

#include <deque>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

#include "osquery/core/sqlite_util.h"
#include "osquery/filesystem.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace core {

const std::string kTestQuery = "SELECT * FROM test_table";

sqlite3* createTestDB() {
  sqlite3* db = createDB();
  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE test_table ("
      "username varchar(30) primary key, "
      "age int"
      ")",
      "INSERT INTO test_table VALUES (\"mike\", 23)",
      "INSERT INTO test_table VALUES (\"matt\", 24)"};
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

osquery::OsqueryScheduledQuery getOsqueryScheduledQuery() {
  osquery::OsqueryScheduledQuery q;
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

std::pair<boost::property_tree::ptree, DiffResults> getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  pt::ptree root;
  root.add_child("added", qd.first);
  root.add_child("removed", qd.first);

  return std::make_pair(root, diff_results);
}

std::pair<std::string, osquery::DiffResults>
getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<pt::ptree, osquery::HistoricalQueryResults>
getSerializedHistoricalQueryResults() {
  auto qd = getSerializedQueryData();
  auto dr = getSerializedDiffResults();
  HistoricalQueryResults r;
  r.mostRecentResults.first = 2;
  r.mostRecentResults.second = qd.second;

  pt::ptree root;

  pt::ptree mostRecentResults;
  mostRecentResults.add_child("2", qd.first);
  root.add_child("mostRecentResults", mostRecentResults);

  return std::make_pair(root, r);
}

std::pair<std::string, osquery::HistoricalQueryResults>
getSerializedHistoricalQueryResultsJSON() {
  auto results = getSerializedHistoricalQueryResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<boost::property_tree::ptree, osquery::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItem() {
  ScheduledQueryLogItem i;
  pt::ptree root;
  auto dr = getSerializedDiffResults();
  i.diffResults = dr.second;
  i.name = "foobar";
  i.calendarTime = "Mon Aug 25 12:10:57 2014";
  i.unixTime = 1408993857;
  i.hostname = "foobaz";
  root.add_child("diffResults", dr.first);
  root.put<std::string>("name", "foobar");
  root.put<std::string>("hostname", "foobaz");
  root.put<std::string>("calendarTime", "Mon Aug 25 12:10:57 2014");
  root.put<int>("unixTime", 1408993857);
  return std::make_pair(root, i);
}

std::pair<std::string, osquery::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItemJSON() {
  auto results = getSerializedScheduledQueryLogItem();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::vector<SplitStringTestData> generateSplitStringTestData() {
  SplitStringTestData s1;
  s1.test_string = "a b\tc";
  s1.test_vector = {"a", "b", "c"};

  SplitStringTestData s2;
  s2.test_string = " a b   c";
  s2.test_vector = {"a", "b", "c"};

  SplitStringTestData s3;
  s3.test_string = "  a     b   c";
  s3.test_vector = {"a", "b", "c"};

  return {s1, s2, s3};
}

std::string getCACertificateContent() {
  std::string content = R"(
MIIESzCCAzOgAwIBAgIJAI1bGeY2YPlhMA0GCSqGSIb3DQEBBQUAMIG7MQswCQYD
VQQGEwItLTESMBAGA1UECAwJU29tZVN0YXRlMREwDwYDVQQHDAhTb21lQ2l0eTEZ
MBcGA1UECgwQU29tZU9yZ2FuaXphdGlvbjEfMB0GA1UECwwWU29tZU9yZ2FuaXph
dGlvbmFsVW5pdDEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkwJwYJ
KoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjAeFw0xNDA4MTkx
OTEyMTZaFw0xNTA4MTkxOTEyMTZaMIG7MQswCQYDVQQGEwItLTESMBAGA1UECAwJ
U29tZVN0YXRlMREwDwYDVQQHDAhTb21lQ2l0eTEZMBcGA1UECgwQU29tZU9yZ2Fu
aXphdGlvbjEfMB0GA1UECwwWU29tZU9yZ2FuaXphdGlvbmFsVW5pdDEeMBwGA1UE
AwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkwJwYJKoZIhvcNAQkBFhpyb290QGxv
Y2FsaG9zdC5sb2NhbGRvbWFpbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAM6EsaVoMaHrYqH/s4YlhF6ke1XmUhzksB2eqpNqdgZw1JcZi9droRpuYmIf
bNyvWqUffHW9mKRv+udF5Woueshn+7Kj9YnnL9jfMzFaVEC8WRwWk54RIdNkxgFq
dqlaiwBWLvZkNUS9k/nugxVTbNu/GTqQlUG1XsIWBDJ2qRqniRfMKrfBKOxPYCZA
l7KeFguRA+xOsA7/71OMXJZKneMSWN8duTQCFt7uYCQXWc/IV6BfKTaR/ZQQ4w7/
iEMYPMZPSNprjun7rx0r2zPZGyrkGSCiS+4e+dfy0NbmYXodGHDxb/vBlm4q8CqF
OoH9aq0F/3581uZcuvU2ydX/LWcCAwEAAaNQME4wHQYDVR0OBBYEFPK5mwDg7mDV
fEJs4+ZOP9xvZBHAMB8GA1UdIwQYMBaAFPK5mwDg7mDVfEJs4+ZOP9xvZBHAMAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAKNNP6f0JKxBtfq8hakrhHyl
cSN83SmVPcrsTLeaW8w0hi+JOtNOjD9sM8KNSbmLXfhRH4yPqYV+0dpJi5+SeelW
DjxZwbcFoI4EEu+zqufTUpu0T51eqnGvIedlIu1i2CiaoAJEmAN2OKQuN7uIQW27
2gL/RS+DVkevaidLRh7q2QI23B0n1XZuyEUiUKB1YfTPrupMZkostuyGybAJaxrc
ONmxUsB38pWJRCef9N/5APS74uIesfxSvEZXcXfPA+wrQY0yXn+bsEhz9pJOxZvD
WxULUHBC6qH9gAlKEqZYS3CwpCEl/Blznwi30r4CwwQ6dLfeXoPQDxAt7LyPpV4=
)";
  return content;
}

std::string getEtcHostsContent() {
  std::string content = R"(
    ##
    # Host Database
    #
    # localhost is used to configure the loopback interface
    # when the system is booting.  Do not change this entry.
    ##
    127.0.0.1       localhost
    255.255.255.255 broadcasthost
    ::1             localhost
    fe80::1%lo0     localhost
    )";
  return content;
}

osquery::QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;

  row1["address"] = "127.0.0.1";
  row1["hostnames"] = "localhost";
  row2["address"] = "255.255.255.255";
  row2["hostnames"] = "broadcasthost";
  row3["address"] = "::1";
  row3["hostnames"] = "localhost";
  row4["address"] = "fe80::1%lo0";
  row4["hostnames"] = "localhost";
  return {row1, row2, row3, row4};
}
}
}
