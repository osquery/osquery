/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <deque>
#include <sstream>
#include <chrono>

#include <time.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/filesystem/operations.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"
#include "osquery/database/db_handle.h"

namespace fs = boost::filesystem;

namespace osquery {
std::string kFakeDirectory = "";

DECLARE_string(database_path);
DECLARE_string(extensions_socket);
DECLARE_string(modules_autoload);
DECLARE_string(extensions_autoload);
DECLARE_bool(disable_logging);

typedef std::chrono::high_resolution_clock chrono_clock;

void initTesting() {
  // Allow unit test execution from anywhere in the osquery source/build tree.
  while (osquery::kTestDataPath != "/") {
    if (!fs::exists(osquery::kTestDataPath)) {
      osquery::kTestDataPath =
          osquery::kTestDataPath.substr(3, osquery::kTestDataPath.size());
    } else {
      break;
    }
  }

  // Seed the random number generator, some tests generate temporary files
  // ports, sockets, etc using random numbers.
  std::srand(chrono_clock::now().time_since_epoch().count());

  // Set safe default values for path-based flags.
  // Specific unittests may edit flags temporarily.
  std::string testWorkingDirectory =
      kTestWorkingDirectory + std::to_string(getuid()) + "/";
  kFakeDirectory = testWorkingDirectory + kFakeDirectoryName;

  fs::remove_all(testWorkingDirectory);
  fs::create_directories(testWorkingDirectory);
  FLAGS_database_path = testWorkingDirectory + "unittests.db";
  FLAGS_extensions_socket = testWorkingDirectory + "unittests.em";
  FLAGS_extensions_autoload = testWorkingDirectory + "unittests-ext.load";
  FLAGS_modules_autoload = testWorkingDirectory + "unittests-mod.load";
  FLAGS_disable_logging = true;

  // Create a default DBHandle instance before unittests.
  (void)DBHandle::getInstance();
}

/// Most tests will use binary or disk-backed content for parsing tests.
#ifndef OSQUERY_BUILD_SDK
std::string kTestDataPath = "../../../tools/tests/";
#else
std::string kTestDataPath = "../../../../tools/tests/";
#endif

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

std::vector<std::pair<std::string, QueryData> > getTestDBResultStream() {
  std::vector<std::pair<std::string, QueryData> > results;

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

ScheduledQuery getOsqueryScheduledQuery() {
  ScheduledQuery sq;
  sq.query = "SELECT filename FROM fs WHERE path = '/bin' ORDER BY filename";
  sq.interval = 5;
  return sq;
}

std::pair<pt::ptree, Row> getSerializedRow() {
  Row r;
  r["foo"] = "bar";
  r["meaning_of_life"] = "42";
  pt::ptree arr;
  arr.put<std::string>("foo", "bar");
  arr.put<std::string>("meaning_of_life", "42");
  return std::make_pair(arr, r);
}

std::pair<pt::ptree, QueryData> getSerializedQueryData() {
  auto r = getSerializedRow();
  QueryData q = {r.second, r.second};
  pt::ptree arr;
  arr.push_back(std::make_pair("", r.first));
  arr.push_back(std::make_pair("", r.first));
  return std::make_pair(arr, q);
}

std::pair<pt::ptree, DiffResults> getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  pt::ptree root;
  root.add_child("added", qd.first);
  root.add_child("removed", qd.first);

  return std::make_pair(root, diff_results);
}

std::pair<std::string, DiffResults> getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();
  std::ostringstream ss;
  pt::write_json(ss, results.first, false);
  return std::make_pair(ss.str(), results.second);
}

std::pair<std::string, QueryData> getSerializedQueryDataJSON() {
  auto results = getSerializedQueryData();
  std::ostringstream ss;
  pt::write_json(ss, results.first, false);
  return std::make_pair(ss.str(), results.second);
}

std::pair<pt::ptree, QueryLogItem> getSerializedQueryLogItem() {
  QueryLogItem i;
  pt::ptree root;
  auto dr = getSerializedDiffResults();
  i.results = dr.second;
  i.name = "foobar";
  i.calendar_time = "Mon Aug 25 12:10:57 2014";
  i.time = 1408993857;
  i.identifier = "foobaz";
  root.add_child("diffResults", dr.first);
  root.put<std::string>("name", "foobar");
  root.put<std::string>("hostIdentifier", "foobaz");
  root.put<std::string>("calendarTime", "Mon Aug 25 12:10:57 2014");
  root.put<int>("unixTime", 1408993857);
  return std::make_pair(root, i);
}

std::pair<std::string, QueryLogItem> getSerializedQueryLogItemJSON() {
  auto results = getSerializedQueryLogItem();

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
  std::string content;
  readFile(kTestDataPath + "test_cert.pem", content);
  return content;
}

std::string getEtcHostsContent() {
  std::string content;
  readFile(kTestDataPath + "test_hosts.txt", content);
  return content;
}

std::string getEtcProtocolsContent() {
  std::string content;
  readFile(kTestDataPath + "test_protocols.txt", content);
  return content;
}

QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;
  Row row5;
  Row row6;

  row1["address"] = "127.0.0.1";
  row1["hostnames"] = "localhost";
  row2["address"] = "255.255.255.255";
  row2["hostnames"] = "broadcasthost";
  row3["address"] = "::1";
  row3["hostnames"] = "localhost";
  row4["address"] = "fe80::1%lo0";
  row4["hostnames"] = "localhost";
  row5["address"] = "127.0.0.1";
  row5["hostnames"] = "example.com example";
  row6["address"] = "127.0.0.1";
  row6["hostnames"] = "example.net";
  return {row1, row2, row3, row4, row5, row6};
}

::std::ostream& operator<<(::std::ostream& os, const Status& s) {
  return os << "Status(" << s.getCode() << ", \"" << s.getMessage() << "\")";
}

QueryData getEtcProtocolsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;

  row1["name"] = "ip";
  row1["number"] = "0";
  row1["alias"] = "IP";
  row1["comment"] = "internet protocol, pseudo protocol number";
  row2["name"] = "icmp";
  row2["number"] = "1";
  row2["alias"] = "ICMP";
  row2["comment"] = "internet control message protocol";
  row3["name"] = "tcp";
  row3["number"] = "6";
  row3["alias"] = "TCP";
  row3["comment"] = "transmission control protocol";

  return {row1, row2, row3};
}

void createMockFileStructure() {
  fs::create_directories(kFakeDirectory + "/deep11/deep2/deep3/");
  fs::create_directories(kFakeDirectory + "/deep1/deep2/");
  writeTextFile(kFakeDirectory + "/root.txt", "root");
  writeTextFile(kFakeDirectory + "/door.txt", "toor");
  writeTextFile(kFakeDirectory + "/roto.txt", "roto");
  writeTextFile(kFakeDirectory + "/deep1/level1.txt", "l1");
  writeTextFile(kFakeDirectory + "/deep11/not_bash", "l1");
  writeTextFile(kFakeDirectory + "/deep1/deep2/level2.txt", "l2");

  writeTextFile(kFakeDirectory + "/deep11/level1.txt", "l1");
  writeTextFile(kFakeDirectory + "/deep11/deep2/level2.txt", "l2");
  writeTextFile(kFakeDirectory + "/deep11/deep2/deep3/level3.txt", "l3");

  boost::system::error_code ec;
  fs::create_symlink(
      kFakeDirectory + "/root.txt", kFakeDirectory + "/root2.txt", ec);
}

void tearDownMockFileStructure() {
  boost::filesystem::remove_all(kFakeDirectory);
}
}
