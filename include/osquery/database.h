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

#include <atomic>
#include <map>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/registry.h>
#include <osquery/status.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace osquery {

/**
 * @brief A list of supported backing storage categories: called domains.
 *
 * RocksDB has a concept of "column families" which are kind of like tables
 * in other databases. kDomains is populated with a list of all column
 * families. If a string exists in kDomains, it's a column family in the
 * database.
 *
 * For SQLite-backed storage these are tables using a keyed index.
 */
extern const std::vector<std::string> kDomains;

/**
 * @brief A backing storage domain name, used for key/value based storage.
 *
 * There are certain "cached" variables such as a node-unique UUID or negotiated
 * 'node_key' following enrollment. If a value or setting must persist between
 * osqueryi or osqueryd runs it should be stored using the kPersistentSetting%s
 * domain.
 */
extern const std::string kPersistentSettings;

/// The "domain" where the results of scheduled queries are stored.
extern const std::string kQueries;

/// The "domain" where event results are stored, queued for querytime retrieval.
extern const std::string kEvents;

/// The "domain" where the results of carve queries are stored.
extern const std::string kCarves;

/**
 * @brief The "domain" where buffered log results are stored.
 *
 * Logger plugins may shuttle logs to a remote endpoint or API call
 * asynchronously. The backing store can be used to buffer results and status
 * logs until the logger plugin-specific thread decided to flush.
 */
extern const std::string kLogs;

/**
 * @brief A variant type for the SQLite type affinities.
 */
using RowData = std::string;

/**
 * @brief A single row from a database query
 *
 * Row is a simple map where individual column names are keys, which map to
 * the Row's respective value
 */
using Row = std::map<std::string, RowData>;

/**
 * @brief A vector of column names associated with a query
 *
 * ColumnNames is a vector of the column names, in order, returned by a query.
 */
using ColumnNames = std::vector<std::string>;

/**
 * @brief Serialize a Row into a property tree
 *
 * @param r the Row to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeRow(const Row& r, boost::property_tree::ptree& tree);
Status serializeRowRJ(const Row& r, rapidjson::Document& d);

/**
 * @brief Serialize a Row object into a JSON string
 *
 * @param r the Row to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeRowJSON(const Row& r, std::string& json);
Status serializeRowJSONRJ(const Row& r, std::string& json);

/**
 * @brief Deserialize a Row object from a property tree
 *
 * @param tree the input property tree
 * @param r the output Row structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRow(const boost::property_tree::ptree& tree, Row& r);

Status deserializeRowRJ(const rapidjson::Value& v, Row& r);

/**
 * @brief Deserialize a Row object from a JSON string
 *
 * @param json the input JSON string
 * @param r the output Row structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRowJSON(const std::string& json, Row& r);
Status deserializeRowJSONRJ(const std::string& json, Row& r);

/**
 * @brief The result set returned from a osquery SQL query
 *
 * QueryData is the canonical way to represent the results of SQL queries in
 * osquery. It's just a vector of Row's.
 */
using QueryData = std::vector<Row>;

/**
 * @brief Serialize a QueryData object into a property tree
 *
 * @param q the QueryData to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryData(const QueryData& q,
                          boost::property_tree::ptree& tree);

Status serializeQueryDataRJ(const QueryData& q, rapidjson::Document& d);

/**
 * @brief Serialize a QueryData object into a property tree
 *
 * @param q the QueryData to serialize
 * @param cols the TableColumn vector indicating column order
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryData(const QueryData& q,
                          const ColumnNames& cols,
                          boost::property_tree::ptree& tree);

Status serializeQueryDataRJ(const QueryData& q,
                            const ColumnNames& cols,
                            rapidjson::Document& d);

/**
 * @brief Serialize a QueryData object into a JSON string
 *
 * @param q the QueryData to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryDataJSON(const QueryData& q, std::string& json);

Status serializeQueryDataJSONRJ(const QueryData& q, std::string& json);

/// Inverse of serializeQueryData, convert property tree to QueryData.
Status deserializeQueryData(const boost::property_tree::ptree& tree,
                            QueryData& qd);

/// Inverse of serializeQueryData, convert property tree to QueryData.
Status deserializeQueryDataRJ(const rapidjson::Value& v, QueryData& qd);

/// Inverse of serializeQueryDataJSON, convert a JSON string to QueryData.
Status deserializeQueryDataJSON(const std::string& json, QueryData& qd);

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
  bool operator!=(const DiffResults& comp) const {
    return !(*this == comp);
  }
};

/**
 * @brief Serialize a DiffResults object into a property tree
 *
 * @param d the DiffResults to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDiffResults(const DiffResults& d,
                            boost::property_tree::ptree& tree);

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
 * non-ASCII characters with their \\u encoding.
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
 * @brief performance statistics about a query
 */
struct QueryPerformance {
  /// Number of executions.
  size_t executions;

  /// Last UNIX time in seconds the query was executed successfully.
  size_t last_executed;

  /// Total wall time taken
  unsigned long long int wall_time;

  /// Total user time (cycles)
  unsigned long long int user_time;

  /// Total system time (cycles)
  unsigned long long int system_time;

  /// Average memory differentials. This should be near 0.
  unsigned long long int average_memory;

  /// Total characters, bytes, generated by query.
  unsigned long long int output_size;

  QueryPerformance()
      : executions(0),
        last_executed(0),
        wall_time(0),
        user_time(0),
        system_time(0),
        average_memory(0),
        output_size(0) {}
};

/**
 * @brief Represents the relevant parameters of a scheduled query.
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

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery() : interval(0), splayed_interval(0) {}

  /// equals operator
  bool operator==(const ScheduledQuery& comp) const {
    return (comp.query == query) && (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const ScheduledQuery& comp) const {
    return !(*this == comp);
  }
};

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
  size_t time{0};

  /// The time that the query was executed, an ASCII string.
  std::string calendar_time;

  /// A set of additional fields to emit with the log line.
  std::map<std::string, std::string> decorations;

  /// equals operator
  bool operator==(const QueryLogItem& comp) const {
    return (comp.results == results) && (comp.name == name);
  }

  /// not equals operator
  bool operator!=(const QueryLogItem& comp) const {
    return !(*this == comp);
  }
};

/**
 * @brief Serialize a QueryLogItem object into a property tree
 *
 * @param item the QueryLogItem to serialize
 * @param tree the output property tree
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItem(const QueryLogItem& item,
                             boost::property_tree::ptree& tree);

/**
 * @brief Serialize a QueryLogItem object into a JSON string
 *
 * @param item the QueryLogItem to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemJSON(const QueryLogItem& item, std::string& json);

/// Inverse of serializeQueryLogItem, convert property tree to QueryLogItem.
Status deserializeQueryLogItem(const boost::property_tree::ptree& tree,
                               QueryLogItem& item);

/// Inverse of serializeQueryLogItem, convert a JSON string to QueryLogItem.
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
Status serializeQueryLogItemAsEvents(const QueryLogItem& item,
                                     boost::property_tree::ptree& tree);

/**
 * @brief Serialize a QueryLogItem object into a JSON string of events,
 * a list of actions.
 *
 * @param i the QueryLogItem to serialize
 * @param items vector of JSON output strings
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemAsEventsJSON(const QueryLogItem& i,
                                         std::vector<std::string>& items);

/**
 * @brief An osquery backing storage (database) type that persists executions.
 *
 * The osquery tools need a high-performance storage and indexing mechanism for
 * storing intermediate results from EventPublisher%s, persisting one-time
 * generated values, and performing non-memory backed differentials.
 *
 * Practically, osquery is built around RocksDB's performance guarantees and
 * all of the internal APIs expect RocksDB's indexing and read performance.
 * However, access to this representation of a backing-store is still abstracted
 * to removing RocksDB as a dependency for the osquery SDK.
 */
class DatabasePlugin : public Plugin {
 public:
  /**
   * @brief Perform a domain and key lookup from the backing store.
   *
   * Database value access indexing is abstracted into domains and keys.
   * Both are string values but exist separately for simple indexing without
   * API-enforcing tokenization. In some cases we do add a component-specific
   * tokeninzation to keys.
   *
   * @param domain A string value representing abstract storage indexing.
   * @param key A string value representing the lookup/retrieval key.
   * @param value The output parameter, left empty if the key does not exist.
   * @return Failure if the data could not be accessed. It is up to the plugin
   * to determine if a missing key means a non-success status.
   */
  virtual Status get(const std::string& domain,
                     const std::string& key,
                     std::string& value) const = 0;

  /**
   * @brief Store a string-represented value using a domain and key index.
   *
   * See DatabasePlugin::get for discussion around domain and key use.
   *
   * @param domain A string value representing abstract storage indexing.
   * @param key A string value representing the lookup/retrieval key.
   * @param value A string value representing the data.
   * @return Failure if the data could not be stored. It is up to the plugin
   * to determine if a conflict/overwrite should return different status text.
   */
  virtual Status put(const std::string& domain,
                     const std::string& key,
                     const std::string& value) = 0;

  /// Data removal method.
  virtual Status remove(const std::string& domain, const std::string& k) = 0;

  /// Data removal with range bounds.
  virtual Status removeRange(const std::string& domain,
                             const std::string& low,
                             const std::string& high) = 0;

  virtual Status scan(const std::string& domain,
                      std::vector<std::string>& results,
                      const std::string& prefix,
                      size_t max = 0) const {
    return Status(0, "Not used");
  }

  /**
   * @brief Shutdown the database and release initialization resources.
   *
   * Assume that a plugin may override #tearDown and choose to close resources
   * when the registry is stopping. Most plugins will implement a mutex around
   * initialization and destruction and assume #setUp and #tearDown will
   * dictate the flow in most situations.
   */
  virtual ~DatabasePlugin() {}

  /**
   * @brief Support the registry calling API for extensions.
   *
   * The database plugin "fast-calls" directly to local plugins.
   * Extensions cannot use an extension-local backing store so their requests
   * are routed like all other plugins.
   */
  Status call(const PluginRequest& request, PluginResponse& response) override;

 public:
  /// Database-specific workflow: reset the originally request instance.
  virtual Status reset() final;

  /// Database-specific workflow: perform an initialize, then reset.
  bool checkDB();

  /// Require all DBHandle accesses to open a read and write handle.
  static void setRequireWrite(bool rw) {
    kDBRequireWrite = rw;
  }

  /// Allow DBHandle creations.
  static void setAllowOpen(bool ao) {
    kDBAllowOpen = ao;
  }

 public:
  /// Control availability of the RocksDB handle (default false).
  static std::atomic<bool> kDBAllowOpen;

  /// The database must be opened in a R/W mode (default false).
  static std::atomic<bool> kDBRequireWrite;

  /// An internal mutex around database sanity checking.
  static std::atomic<bool> kDBChecking;

  /// An internal status protecting database access.
  static std::atomic<bool> kDBInitialized;

 public:
  /**
   * @brief Allow the initializer to check the active database plugin.
   *
   * Unlink the initializer's Initializer::initActivePlugin helper method, the
   * database plugin should always be within the core. There is no need to
   * discover the active plugin via the registry or extensions API.
   *
   * The database should setUp in preparation for accesses.
   */
  static Status initPlugin();

  /// Allow shutdown before exit.
  static void shutdown();

 protected:
  /// The database was opened in a ReadOnly mode.
  bool read_only_{false};

  /// Original requested path on disk.
  std::string path_;
};

/**
 * @brief Lookup a value from the active osquery DatabasePlugin storage.
 *
 * See DatabasePlugin::get for discussion around domain and key use.
 * Extensions, components, plugins, and core code should use getDatabaseValue
 * as a wrapper around the current tool's choice of a backing storage plugin.
 *
 * @param domain A string value representing abstract storage indexing.
 * @param key A string value representing the lookup/retrieval key.
 * @param value The output parameter, left empty if the key does not exist.
 * @return Storage operation status.
 */
Status getDatabaseValue(const std::string& domain,
                        const std::string& key,
                        std::string& value);

/**
 * @brief Set or put a value into the active osquery DatabasePlugin storage.
 *
 * See DatabasePlugin::get for discussion around domain and key use.
 * Extensions, components, plugins, and core code should use setDatabaseValue
 * as a wrapper around the current tool's choice of a backing storage plugin.
 *
 * @param domain A string value representing abstract storage indexing.
 * @param key A string value representing the lookup/retrieval key.
 * @param value A string value representing the data.
 * @return Storage operation status.
 */
Status setDatabaseValue(const std::string& domain,
                        const std::string& key,
                        const std::string& value);

/// Remove a domain/key identified value from backing-store.
Status deleteDatabaseValue(const std::string& domain, const std::string& key);

/// Remove a range of keys in domain.
Status deleteDatabaseRange(const std::string& domain,
                           const std::string& low,
                           const std::string& high);

/// Get a list of keys for a given domain.
Status scanDatabaseKeys(const std::string& domain,
                        std::vector<std::string>& keys,
                        size_t max = 0);

/// Get a list of keys for a given domain.
Status scanDatabaseKeys(const std::string& domain,
                        std::vector<std::string>& keys,
                        const std::string& prefix,
                        size_t max = 0);

/// Allow callers to reload or reset the database plugin.
void resetDatabase();

/// Allow callers to scan each column family and print each value.
void dumpDatabase();
}
