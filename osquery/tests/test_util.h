/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>

namespace pt = boost::property_tree;

namespace osquery {

/// Init function for tests and benchmarks.
void initTesting();

/// Cleanup/stop function for tests and benchmarks.
void shutdownTesting();

/// Any SQL-dependent tests should use kTestQuery for a pre-populated example.
const std::string kTestQuery{"SELECT * FROM test_table"};

/// A fake directory tree should be used for filesystem iterator testing.
const std::string kFakeDirectoryName{"fstree"};

/// Tests can be run from within the source or build directory.
/// The test initializer will attempt to discovery the current working path.
extern std::string kTestDataPath;

/// Tests should limit intermediate input/output to a working directory.
/// Config data, logging results, and intermediate database/caching usage.
extern std::string kTestWorkingDirectory;
extern std::string kFakeDirectory;

// Get an example generate config with one static source name to JSON content.
std::map<std::string, std::string> getTestConfigMap();

pt::ptree getExamplePacksConfig();
pt::ptree getUnrestrictedPack();
pt::ptree getRestrictedPack();
pt::ptree getPackWithDiscovery();
pt::ptree getPackWithValidDiscovery();
pt::ptree getPackWithFakeVersion();

ScheduledQuery getOsqueryScheduledQuery();

// getTestDBExpectedResults returns the results of kTestQuery of the table that
// initially gets returned from createTestDB()
QueryData getTestDBExpectedResults();

// Starting with the dataset returned by createTestDB(), getTestDBResultStream
// returns a vector of std::pair's where pair.first is the query that would
// need to be performed on the dataset to make the results be pair.second
std::vector<std::pair<std::string, QueryData> > getTestDBResultStream();

// getSerializedRowColumnNames returns a vector of test column names that
// are in alphabetical order. If unordered_and_repeated is true, the
// vector includes a repeated column name and is in non-alphabetical order
ColumnNames getSerializedRowColumnNames(bool unordered_and_repeated);

// getSerializedRow() return an std::pair where pair->first is a string which
// should serialize to pair->second. pair->second should deserialize
// to pair->first
std::pair<pt::ptree, Row> getSerializedRow(bool unordered_and_repeated = false);

// getSerializedQueryData() return an std::pair where pair->first is a string
// which should serialize to pair->second. pair->second should
// deserialize to pair->first. getSerializedQueryDataWithColumnOrder
// returns a pair where pair->second is a tree that has a repeated column and
// the child nodes are not in alphabetical order
std::pair<pt::ptree, QueryData> getSerializedQueryData();
std::pair<pt::ptree, QueryData> getSerializedQueryDataWithColumnOrder();
std::pair<std::string, QueryData> getSerializedQueryDataJSON();

// getSerializedDiffResults() return an std::pair where pair->first is a string
// which should serialize to pair->second. pair->second should
// deserialize to pair->first
std::pair<pt::ptree, DiffResults> getSerializedDiffResults();
std::pair<std::string, DiffResults> getSerializedDiffResultsJSON();

// getSerializedQueryLogItem() return an std::pair where pair->first
// is a string which should serialize to pair->second. pair->second
// should deserialize to pair->first
std::pair<pt::ptree, QueryLogItem> getSerializedQueryLogItem();
std::pair<std::string, QueryLogItem> getSerializedQueryLogItemJSON();

// generate content for a PEM-encoded certificate
std::string getCACertificateContent();

// generate the content that would be found in an /etc/hosts file
std::string getEtcHostsContent();

// generate the content that would be found in an /etc/protocols file
std::string getEtcProtocolsContent();

// generate the expected data that getEtcHostsContent() should parse into
QueryData getEtcHostsExpectedResults();

// generate the expected data that getEtcProtocolsContent() should parse into
QueryData getEtcProtocolsExpectedResults();

// the three items that you need to test osquery::splitString
struct SplitStringTestData {
  std::string test_string;
  std::string delim;
  std::vector<std::string> test_vector;
};

// generate a set of test data to test osquery::splitString
std::vector<SplitStringTestData> generateSplitStringTestData();

// generate a small directory structure for testing
void createMockFileStructure();

// remove the small directory structure used for testing
void tearDownMockFileStructure();
}

