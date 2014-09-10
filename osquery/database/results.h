// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <deque>
#include <map>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include "osquery/status.h"

namespace osquery {
namespace db {

/////////////////////////////////////////////////////////////////////////////
// Row - the representation of a row in a set of database results. Row is a
// simple map where individual column names are keys, which map to the Row's
// respective value
/////////////////////////////////////////////////////////////////////////////

// Row represents a single row from a database query
typedef std::map<std::string, std::string> Row;

// serializeRow accepts a const reference to a row and a non-const reference to
// a ptree. The contents of const Row r will be serialized into ptree tree and
// an osquery::Status will be returned indicating the success or failure
// of the operation.
osquery::Status serializeRow(const Row& r, boost::property_tree::ptree& tree);

/////////////////////////////////////////////////////////////////////////////
// QueryData - the representation of a database query result set. It's a
// vector of rows
/////////////////////////////////////////////////////////////////////////////

// QueryData represents an entire result set from a database query
typedef std::vector<Row> QueryData;

// serializeQueryData accepts a const reference to a QueryData and a non-const
// reference to a ptree. The contents of const QueryData q will be serialized
// into ptree tree and an osquery::Status will be returned indicating the
// success or failure of the operation.
osquery::Status serializeQueryData(const QueryData& q,
                                   boost::property_tree::ptree& tree);

/////////////////////////////////////////////////////////////////////////////
// DiffResults - the representation of two diffed QueryData result sets.
// Given and old and new QueryData, DiffResults indicates the "added" subset
// of rows and the "removed" subset of rows
/////////////////////////////////////////////////////////////////////////////

// struct with two fields, added and removed (both of which are vector<string>)
struct DiffResults {
  // vector of added rows
  QueryData added;

  // vector of removed rows
  QueryData removed;

  // equals operator
  bool operator==(const DiffResults& comp) const {
    return (comp.added == added) && (comp.removed == removed);
  }

  // not equals operator
  bool operator!=(const DiffResults& comp) const { return !(*this == comp); }
};

// typedef so we can say "DiffResults" instead of "struct DiffResults"
typedef struct DiffResults DiffResults;

// serializeDiffResults accepts a const reference to a DiffResults and a
// non-const reference to a ptree. The contents of const DiffResults d will be
// serialized into ptree tree and an osquery::Status will be returned
// indicating the success or failure of the operation.
osquery::Status serializeDiffResults(const DiffResults& d,
                                     boost::property_tree::ptree& tree);

// serializeDiffResultsJSON accepts a const reference to a DiffResults struct
// and a non-const reference to a std::string.  The contents of const
// DiffResults d will be serialized into std::string json and an
// osquery::Status will be returned indicating the success or failure of
// the operation.
osquery::Status serializeDiffResultsJSON(const DiffResults& d,
                                         std::string& json);

// given a const reference to the queryData results of two queries, compute
// their difference
DiffResults diff(const QueryData& old_, const QueryData& new_);

/////////////////////////////////////////////////////////////////////////////
// HistoricalQueryResults - the representation of the historical results of
// a particular scheduled database query.
/////////////////////////////////////////////////////////////////////////////

// HistoricalQueryResults is a struct which represents a scheduled query's
// historical results on disk
struct HistoricalQueryResults {
  // mostRecentResults->first is the timestamp of the most recent results and
  // mostRecentResults->second is the query result data of the most recent
  // query
  std::pair<int, QueryData> mostRecentResults;

  // equals operator
  bool operator==(const HistoricalQueryResults& comp) const {
    return (comp.mostRecentResults == mostRecentResults);
  }

  // not equals operator
  bool operator!=(const HistoricalQueryResults& comp) const {
    return !(*this == comp);
  }
};

// typedef so we can say "HistoricalQueryResults" instead of
// "struct HistoricalQueryResults"
typedef struct HistoricalQueryResults HistoricalQueryResults;

// serializeHistoricalQueryResults accepts a const reference to a
// HistoricalQueryResults struct and a non-const reference to a ptree. The
// contents of const HistoricalQueryResults r will be serialized into ptree
// tree and an osquery::Status will be returned indicating the success or
// failure of the operation.
osquery::Status serializeHistoricalQueryResults(
    const HistoricalQueryResults& r, boost::property_tree::ptree& tree);

// serializeHistoricalQueryResultsJSON accepts a const reference to a
// HistoricalQueryResults struct and a non-const reference to a std::string.
// The contents of const HistoricalQueryResults r will be serialized into
// std::string json and an osquery::Status will be returned indicating the
// success or failure of the operation.
osquery::Status serializeHistoricalQueryResultsJSON(
    const HistoricalQueryResults& r, std::string& json);

// deserializeHistoricalQueryResults accepts a const reference to a ptree of a
// serialized HistoricalQueryResults struct and a non-const reference to a
// historicalQueryResults struct.  The contents of const ptree tree will be
// serialized into HistoricalQueryResults r and an osquery::Status will be
// returned indicating the success or failure of the operation.
osquery::Status deserializeHistoricalQueryResults(
    const boost::property_tree::ptree& tree, HistoricalQueryResults& r);

// deserializeHistoricalQueryResultsJSON accepts a const reference to an
// std::string of a serialized HistoricalQueryResults struct and a non-const
// reference to a HistoricalQueryResults struct.  The contents of const
// std::string json will be serialized into HistoricalQueryResults r and an
// osquery::Status will be returned indicating the success or failure of
// the operation.
osquery::Status deserializeHistoricalQueryResultsJSON(
    const std::string& json, HistoricalQueryResults& r);

/////////////////////////////////////////////////////////////////////////////
// ScheduledQueryLogItem - the representation of a log result occuring when a
// s schedueld query yields operating system state change.
/////////////////////////////////////////////////////////////////////////////

// struct which represents a logged DiffResults type as well as necessary
// metadata about the DiffResults being logged
struct ScheduledQueryLogItem {
  // the content of the data which was changed as a result of the schedueld
  // query
  DiffResults diffResults;

  // the name of the scheduled query
  std::string name;

  // the hostname of the host which the scheduled query was executed on
  std::string hostname;

  // the time that the query was executed, in unix time
  int unixTime;

  // the time that the query was executed, in ASCII
  std::string calendarTime;

  // equals operator
  bool operator==(const ScheduledQueryLogItem& comp) const {
    return (comp.diffResults == diffResults) && (comp.name == name);
  }

  // not equals operator
  bool operator!=(const ScheduledQueryLogItem& comp) const {
    return !(*this == comp);
  }
};

// serializeScheduledQueryLogItem accepts a const reference to a
// ScheduledQueryLogItem and a non-const reference to a ptree. The contents of
// const ScheduledQueryLogItem i will be serialized into ptree tree and an
// osquery::Status will be returned indicating the success or failure of
// the operation.
osquery::Status serializeScheduledQueryLogItem(
    const ScheduledQueryLogItem& i, boost::property_tree::ptree& tree);

osquery::Status serializeScheduledQueryLogItemJSON(
    const ScheduledQueryLogItem& i, std::string& json);
}
}
