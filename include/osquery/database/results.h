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

#include <map>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/status.h>

namespace pt = boost::property_tree;

namespace osquery {

/////////////////////////////////////////////////////////////////////////////
// Row
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief A variant type for the SQLite type affinities.
 */
typedef std::string RowData;

/**
 * @brief A single row from a database query
 *
 * Row is a simple map where individual column names are keys, which map to
 * the Row's respective value
 */
typedef std::map<std::string, RowData> Row;

/**
 * @brief Serialize a Row into a property tree
 *
 * @param r the Row to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeRow(const Row& r, pt::ptree& tree);

/**
 * @brief Serialize a Row object into a JSON string
 *
 * @param r the Row to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeRowJSON(const Row& r, std::string& json);

/**
 * @brief Deserialize a Row object from a property tree
 *
 * @param tree the input property tree
 * @param r the output Row structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRow(const pt::ptree& tree, Row& r);

/**
 * @brief Deserialize a Row object from a JSON string
 *
 * @param json the input JSON string
 * @param r the output Row structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRowJSON(const std::string& json, Row& r);

/////////////////////////////////////////////////////////////////////////////
// QueryData
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief The result set returned from a osquery SQL query
 *
 * QueryData is the canonical way to represent the results of SQL queries in
 * osquery. It's just a vector of Row's.
 */
typedef std::vector<Row> QueryData;

/**
 * @brief Serialize a QueryData object into a property tree
 *
 * @param q the QueryData to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryData(const QueryData& q, pt::ptree& tree);

/**
 * @brief Serialize a QueryData object into a JSON string
 *
 * @param q the QueryData to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryDataJSON(const QueryData& q, std::string& json);

Status deserializeQueryData(const pt::ptree& tree, QueryData& qd);
Status deserializeQueryDataJSON(const std::string& json, QueryData& qd);

/////////////////////////////////////////////////////////////////////////////
// DiffResults
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief Data structure representing the difference between the results of
 * two queries
 *
 * The representation of two diffed QueryData result sets. Given and old and
 * new QueryData, DiffResults indicates the "added" subset of rows and the
 * "removed" subset of rows.
 */
struct DiffResults {
  /// vector of added rows
  QueryData added;

  /// vector of removed rows
  QueryData removed;

  /// equals operator
  bool operator==(const DiffResults& comp) const {
    return (comp.added == added) && (comp.removed == removed);
  }

  /// not equals operator
  bool operator!=(const DiffResults& comp) const { return !(*this == comp); }
};

/**
 * @brief Serialize a DiffResults object into a property tree
 *
 * @param d the DiffResults to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDiffResults(const DiffResults& d, pt::ptree& tree);

/**
 * @brief Serialize a DiffResults object into a JSON string
 *
 * @param d the DiffResults to serialize
 * @param json the output JSON string
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation
 */
Status serializeDiffResultsJSON(const DiffResults& d, std::string& json);

/**
 * @brief Diff two QueryData objects and create a DiffResults object
 *
 * @param old_ the "old" set of results
 * @param new_ the "new" set of results
 *
 * @return a DiffResults object which indicates the change from old_ to new_
 *
 * @see DiffResults
 */
DiffResults diff(const QueryData& old_, const QueryData& new_);

/**
 * @brief Add a Row to a QueryData if the Row hasn't appeared in the QueryData
 * already
 *
 * Note that this function will iterate through the QueryData list until a
 * given Row is found (or not found). This shouldn't be that significant of an
 * overhead for most use-cases, but it's worth keeping in mind before you use
 * this in it's current state.
 *
 * @param q the QueryData list to append to
 * @param r the Row to add to q
 *
 * @return true if the Row was added to the QueryData, false if it was not
 */
bool addUniqueRowToQueryData(QueryData& q, const Row& r);

/**
 * @brief Construct a new QueryData from an existing one, replacing all
 * non-ASCII characters with their \u encoding.
 *
 * This function is intended as a workaround for
 * https://svn.boost.org/trac/boost/ticket/8883,
 * and will allow rows containing data with non-ASCII characters to be stored in
 * the database and parsed back into a property tree.
 *
 * @param oldData the old QueryData to copy
 * @param newData the new escaped QueryData object
 */
void escapeQueryData(const QueryData& oldData, QueryData& newData);

/**
 * @brief represents the relevant parameters of a scheduled query.
 *
 * Within the context of osqueryd, a scheduled query may have many relevant
 * attributes. Those attributes are represented in this data structure.
 */
struct ScheduledQuery {
  /// The SQL query.
  std::string query;

  /// How often the query should be executed, in second.
  size_t interval;

  /// A temporary splayed internal.
  size_t splayed_interval;

  /// Number of executions.
  size_t executions;

  /// Total wall time taken
  size_t wall_time;

  /// Total user time (cycles)
  size_t user_time;

  /// Total system time (cycles)
  size_t system_time;

  /// Average memory differentials. This should be near 0.
  size_t memory;

  /// Total characters, bytes, generated by query.
  size_t output_size;

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery()
      : interval(0),
        splayed_interval(0),
        executions(0),
        wall_time(0),
        user_time(0),
        system_time(0),
        memory(0),
        output_size(0) {}

  /// equals operator
  bool operator==(const ScheduledQuery& comp) const {
    return (comp.query == query) && (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const ScheduledQuery& comp) const { return !(*this == comp); }
};

/////////////////////////////////////////////////////////////////////////////
// QueryLogItem
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief Query results from a schedule, snapshot, or ad-hoc execution.
 *
 * When a scheduled query yields new results, we need to log that information
 * to our upstream logging receiver. A QueryLogItem contains metadata and
 * results in potentially-differential form for a logger.
 */
struct QueryLogItem {
  /// Differential results from the query.
  DiffResults results;

  /// Optional snapshot results, no differential applied.
  QueryData snapshot_results;

  /// The name of the scheduled query.
  std::string name;

  /// The identifier (hostname, or uuid) of the host.
  std::string identifier;

  /// The time that the query was executed, seconds as UNIX time.
  int time;

  /// The time that the query was executed, an ASCII string.
  std::string calendar_time;

  /// equals operator
  bool operator==(const QueryLogItem& comp) const {
    return (comp.results == results) && (comp.name == name);
  }

  /// not equals operator
  bool operator!=(const QueryLogItem& comp) const { return !(*this == comp); }
};

/**
 * @brief Serialize a QueryLogItem object into a property tree
 *
 * @param item the QueryLogItem to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItem(const QueryLogItem& item, pt::ptree& tree);

/**
 * @brief Serialize a QueryLogItem object into a JSON string
 *
 * @param item the QueryLogItem to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemJSON(const QueryLogItem& item, std::string& json);

Status deserializeQueryLogItem(const pt::ptree& tree, QueryLogItem& item);
Status deserializeQueryLogItemJSON(const std::string& json, QueryLogItem& item);

/**
 * @brief Serialize a QueryLogItem object into a property tree
 * of events, a list of actions.
 *
 * @param item the QueryLogItem to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemAsEvents(const QueryLogItem& item, pt::ptree& tree);

/**
 * @brief Serialize a QueryLogItem object into a JSON string of events,
 * a list of actions.
 *
 * @param i the QueryLogItem to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemAsEventsJSON(const QueryLogItem& i,
                                         std::string& json);
}
