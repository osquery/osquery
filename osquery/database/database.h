/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <string>
#include <vector>

#include <osquery/core/plugins/plugin.h>
#include <osquery/database/idatabaseinterface.h>

namespace osquery {
class Status;
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

/// The key for the DB version
extern const std::string kDbVersionKey;

/// The "domain" where distributed queries are stored.
extern const std::string kDistributedQueries;

/// The "domain" where currently running distributed queries are stored.
extern const std::string kDistributedRunningQueries;

/// The running version of our database schema
const int kDbCurrentVersion = 2;

/**
 * @brief The "domain" where buffered log results are stored.
 *
 * Logger plugins may shuttle logs to a remote endpoint or API call
 * asynchronously. The backing store can be used to buffer results and status
 * logs until the logger plugin-specific thread decided to flush.
 */
extern const std::string kLogs;

// A list of key/str pairs; used for write batching with setDatabaseBatch
using DatabaseStringValueList =
    std::vector<std::pair<std::string, std::string>>;

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
   * tokenization to keys.
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

  virtual Status get(const std::string& domain,
                     const std::string& key,
                     int& value) const = 0;

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

  virtual Status put(const std::string& domain,
                     const std::string& key,
                     int value) = 0;

  virtual Status putBatch(const std::string& domain,
                          const DatabaseStringValueList& data) = 0;

  /// Data removal method.
  virtual Status remove(const std::string& domain, const std::string& k) = 0;

  /// Data removal with range bounds.
  virtual Status removeRange(const std::string& domain,
                             const std::string& low,
                             const std::string& high) = 0;

  virtual Status scan(const std::string& domain,
                      std::vector<std::string>& results,
                      const std::string& prefix,
                      uint64_t max) const;

  /**
   * @brief Shutdown the database and release initialization resources.
   *
   * Assume that a plugin may override #tearDown and choose to close resources
   * when the registry is stopping. Most plugins will implement a mutex around
   * initialization and destruction and assume #setUp and #tearDown will
   * dictate the flow in most situations.
   */
  ~DatabasePlugin() override = default;

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
  Status reset();

  /// Database-specific workflow: perform an initialize, then reset.
  bool checkDB();

 protected:
  /// Check if the database allows opening.
  bool allowOpen() const;

  /// Check if the DB is being checked ;)
  bool checkingDB() const;

 protected:
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

Status getDatabaseValue(const std::string& domain,
                        const std::string& key,
                        int& value);

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

Status setDatabaseValue(const std::string& domain,
                        const std::string& key,
                        int value);

Status setDatabaseBatch(const std::string& domain,
                        const DatabaseStringValueList& data);

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
                        uint64_t max = 0);

/// Allow callers to reload or reset the database plugin.
void resetDatabase();

/// Allow callers to scan each column family and print each value.
void dumpDatabase();

/// Allow database usage creations.
void setDatabaseAllowOpen(bool allow_open = true);

/**
 * @brief Allow a caller to check the active database plugin.
 *
 * There is no need to discover the active plugin via the registry or
 * extensions API.
 *
 * The database should setUp in preparation for accesses.
 */
Status initDatabasePlugin();

/**
 * @brief Helper method for unit test binaries.
 *
 * This allows the database to be opened, disables the database, then calls
 * the normal plugin initialization.
 */
Status initDatabasePluginForTesting();

/// Check if the database has been initialized successfully.
bool databaseInitialized();

/// Allow shutdown before exit.
void shutdownDatabase();

Status ptreeToRapidJSON(const std::string& in, std::string& out);

/**
 * @brief Upgrades the legacy database json format from ptree to RapidJSON
 *
 * This helper function was required as Boost property trees contain json
 * which leverages empty strings for keys in json arrays. This is incompatible
 * with rapidjson, thus we require a converter function to upgrade any cached
 * results in the database.
 *
 * @return Success status of upgrading the database
 */
Status upgradeDatabase(int to_version = kDbCurrentVersion);

/// Returns a database inteface that routes database requests through the
/// registry
IDatabaseInterface& getOsqueryDatabase();
} // namespace osquery
