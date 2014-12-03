// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <sqlite3.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace core {

// kTestQuery is a test query that can be executed against the database
// returned from createTestDB() to result in the dataset returned from
// getTestDBExpectedResults()
extern const std::string kTestQuery;

// createTestDB instantiates a sqlite3 struct and populates it with some test
// data
sqlite3* createTestDB();

// getTestDBExpectedResults returns the results of kTestQuery of the table that
// initially gets returned from createTestDB()
osquery::QueryData getTestDBExpectedResults();

// Starting with the dataset returned by createTestDB(), getTestDBResultStream
// returns a vector of std::pair's where pair.first is the query that would
// need to be performed on the dataset to make the results be pair.second
std::vector<std::pair<std::string, osquery::QueryData> >
getTestDBResultStream();

// getOsqueryScheduledQuery returns a test scheduled query which would normally
// be returned via the config
osquery::OsqueryScheduledQuery getOsqueryScheduledQuery();

// getSerializedRow() return an std::pair where pair->first is a string which
// should serialize to pair->second. Obviously, pair->second should deserialize
// to pair->first
std::pair<boost::property_tree::ptree, osquery::Row> getSerializedRow();

// getSerializedQueryData() return an std::pair where pair->first is a string
// which should serialize to pair->second. Obviously, pair->second should
// deserialize to pair->first
std::pair<boost::property_tree::ptree, osquery::QueryData>
getSerializedQueryData();

// getSerializedDiffResults() return an std::pair where pair->first is a string
// which should serialize to pair->second. Obviously, pair->second should
// deserialize to pair->first
std::pair<boost::property_tree::ptree, osquery::DiffResults>
getSerializedDiffResults();

std::pair<std::string, osquery::DiffResults> getSerializedDiffResultsJSON();

// getSerializedHistoricalQueryResults() return an std::pair where pair->first
// is a string which should serialize to pair->second. Obviously, pair->second
// should deserialize to pair->first
std::pair<boost::property_tree::ptree, osquery::HistoricalQueryResults>
getSerializedHistoricalQueryResults();

std::pair<std::string, osquery::HistoricalQueryResults>
getSerializedHistoricalQueryResultsJSON();

// getSerializedScheduledQueryLogItem() return an std::pair where pair->first
// is a string which should serialize to pair->second. Obviously, pair->second
// should deserialize to pair->first
std::pair<boost::property_tree::ptree, osquery::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItem();

std::pair<std::string, osquery::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItemJSON();

// generate content for a PEM-encoded certificate
std::string getCACertificateContent();

// generate the content that would be found in an /etc/hosts file
std::string getEtcHostsContent();

// generate the expected data that getEtcHostsContent() should parse into
osquery::QueryData getEtcHostsExpectedResults();

// the three items that you need to test osquery::core::splitString
struct SplitStringTestData {
  std::string test_string;
  std::string delim;
  std::vector<std::string> test_vector;
};

// generate a set of test data to test osquery::core::splitString
std::vector<SplitStringTestData> generateSplitStringTestData();
}
}
