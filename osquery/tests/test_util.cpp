/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>
#include <deque>
#include <random>
#include <sstream>
#include <thread>

#include <csignal>
#include <ctime>

#include <boost/filesystem/operations.hpp>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

/// Will be set with initTesting in test harness main.
std::string kFakeDirectory;

/// Will be set with initTesting in test harness main.
std::string kTestWorkingDirectory;

/// The relative path within the source repo to find test content.
std::string kTestDataPath{"../../../tools/tests/"};

DECLARE_string(database_path);
DECLARE_string(extensions_socket);
DECLARE_string(extensions_autoload);
DECLARE_string(enroll_tls_endpoint);
DECLARE_bool(disable_logging);
DECLARE_bool(disable_database);

using chrono_clock = std::chrono::high_resolution_clock;

void initTesting() {
  Config::setStartTime(getUnixTime());

  kToolType = ToolType::TEST;
  if (osquery::isPlatform(PlatformType::TYPE_OSX)) {
    kTestWorkingDirectory = "/private/tmp/osquery-tests";
  } else {
    kTestWorkingDirectory =
        (fs::temp_directory_path() / "osquery-tests").string();
  }

  if (osquery::isPlatform(PlatformType::TYPE_WINDOWS)) {
    kTestDataPath = "../" + kTestDataPath;
  }

  registryAndPluginInit();

  // Allow unit test execution from anywhere in the osquery source/build tree.
  if (fs::exists("test_data/test_inline_pack.conf")) {
    // If the execution occurs within the build/shared directory and shared
    // is pointing to a tmp build directory. See #3414.
    kTestDataPath = "test_data/";
  } else if (fs::exists("../test_data/test_inline_pack.conf")) {
    // ctest executes from the osquery subdirectory. If this is a build/shared
    // link then the test_data directory links to the source repo.
    kTestDataPath = "../test_data/";
  } else {
    while (kTestDataPath.find("tools") != 0) {
      if (!fs::exists(kTestDataPath + "test_inline_pack.conf")) {
        kTestDataPath = kTestDataPath.substr(3, kTestDataPath.size());
      } else {
        break;
      }
    }
  }

  // The tests will fail randomly without test data.
  if (!fs::exists(kTestDataPath)) {
    throw std::runtime_error("Cannot find test data path");
  }

  // Seed the random number generator, some tests generate temporary files
  // ports, sockets, etc using random numbers.
  std::srand(static_cast<unsigned int>(
      chrono_clock::now().time_since_epoch().count()));

  // Set safe default values for path-based flags.
  // Specific unittests may edit flags temporarily.
  kTestWorkingDirectory += std::to_string(platformGetUid()) + "/";
  kFakeDirectory = kTestWorkingDirectory + kFakeDirectoryName;

  fs::remove_all(kTestWorkingDirectory);
  fs::create_directories(kTestWorkingDirectory);
  FLAGS_database_path = kTestWorkingDirectory + "unittests.db";
  FLAGS_extensions_socket = kTestWorkingDirectory + "unittests.em";
  FLAGS_extensions_autoload = kTestWorkingDirectory + "unittests-ext.load";

  FLAGS_disable_logging = true;
  FLAGS_disable_database = true;

  // Tests need a database plugin.
  // Set up the database instance for the unittests.
  DatabasePlugin::setAllowOpen(true);
  DatabasePlugin::initPlugin();

  Initializer::platformSetup();
}

void shutdownTesting() {
  DatabasePlugin::shutdown();

  Initializer::platformTeardown();
}

std::map<std::string, std::string> getTestConfigMap(const std::string& file) {
  std::string content;
  readFile(fs::path(kTestDataPath) / file, content);
  std::map<std::string, std::string> config;
  config["awesome"] = content;
  return config;
}

JSON getExamplePacksConfig() {
  std::string content;
  auto s = readFile(fs::path(kTestDataPath) / "test_inline_pack.conf", content);
  assert(s.ok());
  JSON doc = JSON::newObject();
  doc.fromString(content);
  return doc;
}

/// no discovery queries, no platform restriction
JSON getUnrestrictedPack() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["unrestricted_pack"]);
}

// several restrictions (version, platform, shard)
JSON getRestrictedPack() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["restricted_pack"]);
}

/// 1 discovery query, darwin platform restriction
JSON getPackWithDiscovery() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["discovery_pack"]);
}

/// 1 discovery query which will always pass
JSON getPackWithValidDiscovery() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["valid_discovery_pack"]);
}

/// no discovery queries, no platform restriction, fake version string
JSON getPackWithFakeVersion() {
  auto doc = getExamplePacksConfig();
  return JSON::newFromValue(doc.doc()["packs"]["fake_version_pack"]);
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
      R"(INSERT INTO test_table (username, age) VALUES ("joe", 25))";
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

  std::string q3 = R"(UPDATE test_table SET age = 27 WHERE username = "matt")";
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
      R"(DELETE FROM test_table WHERE username = "matt" AND age = 27)";
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

std::pair<JSON, Row> getSerializedRow(bool unordered_and_repeated) {
  auto cns = getSerializedRowColumnNames(unordered_and_repeated);

  Row r;
  auto doc = JSON::newObject();
  for (const auto& cn : cns) {
    auto c_value = cn + "_value";
    r[cn] = c_value;
    doc.addCopy(cn, c_value);
  }
  return std::make_pair(std::move(doc), r);
}

std::pair<JSON, QueryData> getSerializedQueryData() {
  auto r = getSerializedRow(false);
  QueryData q = {r.second, r.second};

  JSON doc = JSON::newArray();
  auto arr1 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr1);
  doc.push(arr1);

  auto arr2 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr2);
  doc.push(arr2);

  return std::make_pair(std::move(doc), q);
}

std::pair<JSON, QueryData> getSerializedQueryDataWithColumnOrder() {
  auto r = getSerializedRow(true);
  QueryData q = {r.second, r.second};
  JSON doc = JSON::newArray();
  auto arr1 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr1);
  doc.push(arr1);

  auto arr2 = doc.getArray();
  doc.copyFrom(r.first.doc(), arr2);
  doc.push(arr2);

  return std::make_pair(std::move(doc), q);
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

std::pair<std::string, DiffResults> getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, std::move(results.second));
}

std::pair<std::string, QueryData> getSerializedQueryDataJSON() {
  auto results = getSerializedQueryData();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, results.second);
}

std::pair<JSON, QueryLogItem> getSerializedQueryLogItem() {
  std::pair<JSON, QueryLogItem> p;
  QueryLogItem i;
  JSON doc = JSON::newObject();
  auto dr = getSerializedDiffResults();
  i.results = std::move(dr.second);
  i.name = "foobar";
  i.calendar_time = "Mon Aug 25 12:10:57 2014";
  i.time = 1408993857;
  i.identifier = "foobaz";
  i.epoch = 0L;
  i.counter = 0L;

  auto diff_doc = doc.getObject();
  diff_doc.Swap(dr.first.doc());
  doc.add("diffResults", diff_doc);
  doc.addRef("name", "foobar");
  doc.addRef("hostIdentifier", "foobaz");
  doc.addRef("calendarTime", "Mon Aug 25 12:10:57 2014");
  doc.add("unixTime", 1408993857);
  doc.add("epoch", 0_sz);
  doc.add("counter", 0_sz);

  return std::make_pair(std::move(doc), std::move(i));
}

std::pair<std::string, QueryLogItem> getSerializedQueryLogItemJSON() {
  auto results = getSerializedQueryLogItem();
  std::string output;
  results.first.toString(output);
  return std::make_pair(output, std::move(results.second));
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
  readFile(fs::path(kTestDataPath) / "test_cert.pem", content);
  return content;
}

std::string getEtcHostsContent() {
  std::string content;
  readFile(fs::path(kTestDataPath) / "test_hosts.txt", content);
  return content;
}

std::string getEtcHostsIcsContent() {
  std::string content;
  readFile(fs::path(kTestDataPath) / "test_hosts_ics.txt", content);
  return content;
}

std::string getEtcProtocolsContent() {
  std::string content;
  readFile(fs::path(kTestDataPath) / "test_protocols.txt", content);
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

QueryData getEtcHostsIcsExpectedResults() {
  Row row1;

  row1["address"] = "192.168.11.81";
  row1["hostnames"] = "VM-q27rkc8son.mshome.net";
  return {row1};
}

::std::ostream& operator<<(::std::ostream& os, const Status& s) {
  return os << "Status(" << s.getCode() << R"(, ")" << s.getMessage()
            << R"("))";
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

QueryData genRows(EventSubscriberPlugin* sub) {
  auto vtc = new VirtualTableContent();
  QueryContext context(vtc);
  RowGenerator::pull_type generator(std::bind(&EventSubscriberPlugin::genTable,
                                              sub,
                                              std::placeholders::_1,
                                              std::move(context)));

  QueryData results;
  if (!generator) {
    delete vtc;
    return results;
  }

  while (generator) {
    results.push_back(generator.get());
    generator();
  }
  delete vtc;
  return results;
}

void createMockFileStructure() {
  fs::create_directories(kFakeDirectory + "/toplevel/");
  fs::create_directories(kFakeDirectory + "/toplevel/secondlevel1");
  fs::create_directories(kFakeDirectory + "/toplevel/secondlevel2");
  fs::create_directories(kFakeDirectory + "/toplevel/secondlevel3");
  fs::create_directories(kFakeDirectory + "/toplevel/secondlevel3/thirdlevel1");
  fs::create_directories(kFakeDirectory + "/deep11/deep2/deep3/");
  fs::create_directories(kFakeDirectory + "/deep1/deep2/");
  writeTextFile(kFakeDirectory + "/root.txt", "root");
  writeTextFile(kFakeDirectory + "/door.txt", "toor", 0550);
  writeTextFile(kFakeDirectory + "/roto.txt", "roto");
  writeTextFile(kFakeDirectory + "/deep1/level1.txt", "l1");
  writeTextFile(kFakeDirectory + "/deep11/not_bash", "l1");
  writeTextFile(kFakeDirectory + "/deep1/deep2/level2.txt", "l2");

  writeTextFile(kFakeDirectory + "/deep11/level1.txt", "l1");
  writeTextFile(kFakeDirectory + "/deep11/deep2/level2.txt", "l2");
  writeTextFile(kFakeDirectory + "/deep11/deep2/deep3/level3.txt", "l3");

#ifdef WIN32
  writeTextFile(kFakeDirectory + "/root2.txt", "l1");
#else
  boost::system::error_code ec;
  fs::create_symlink(
      kFakeDirectory + "/root.txt", kFakeDirectory + "/root2.txt", ec);
#endif
}

void tearDownMockFileStructure() {
  boost::filesystem::remove_all(kFakeDirectory);
}
} // namespace osquery
