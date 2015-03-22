/*
 *  Copyright (c) 2014, Facebook, Inc.
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

namespace osquery {

// kTestQuery is a test query that can be executed against the database
// returned from createTestDB() to result in the dataset returned from
// getTestDBExpectedResults()
extern const std::string kTestQuery;
extern const std::string kTestDataPath;

const std::string kFakeDirectory = "/tmp/osquery-fstests-pattern";

// getTestDBExpectedResults returns the results of kTestQuery of the table that
// initially gets returned from createTestDB()
QueryData getTestDBExpectedResults();

// Starting with the dataset returned by createTestDB(), getTestDBResultStream
// returns a vector of std::pair's where pair.first is the query that would
// need to be performed on the dataset to make the results be pair.second
std::vector<std::pair<std::string, QueryData> > getTestDBResultStream();

// getOsqueryScheduledQuery returns a test scheduled query which would normally
// be returned via the config
ScheduledQuery getOsqueryScheduledQuery();

// getSerializedRow() return an std::pair where pair->first is a string which
// should serialize to pair->second. pair->second should deserialize
// to pair->first
std::pair<boost::property_tree::ptree, Row> getSerializedRow();

// getSerializedQueryData() return an std::pair where pair->first is a string
// which should serialize to pair->second. pair->second should
// deserialize to pair->first
std::pair<boost::property_tree::ptree, QueryData> getSerializedQueryData();

// getSerializedDiffResults() return an std::pair where pair->first is a string
// which should serialize to pair->second. pair->second should
// deserialize to pair->first
std::pair<boost::property_tree::ptree, DiffResults> getSerializedDiffResults();

std::pair<std::string, DiffResults> getSerializedDiffResultsJSON();

// getSerializedHistoricalQueryResults() return an std::pair where pair->first
// is a string which should serialize to pair->second. pair->second
// should deserialize to pair->first
std::pair<boost::property_tree::ptree, HistoricalQueryResults>
getSerializedHistoricalQueryResults();

std::pair<std::string, HistoricalQueryResults>
getSerializedHistoricalQueryResultsJSON();

// getSerializedScheduledQueryLogItem() return an std::pair where pair->first
// is a string which should serialize to pair->second. pair->second
// should deserialize to pair->first
std::pair<boost::property_tree::ptree, ScheduledQueryLogItem>
getSerializedScheduledQueryLogItem();

std::pair<std::string, ScheduledQueryLogItem>
getSerializedScheduledQueryLogItemJSON();

// generate content for a PEM-encoded certificate
std::string getCACertificateContent();

// generate the content that would be found in an /etc/hosts file
std::string getEtcHostsContent();

// generate the expected data that getEtcHostsContent() should parse into
QueryData getEtcHostsExpectedResults();

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
