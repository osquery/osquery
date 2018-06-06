/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <atomic>
#include <string>
#include <vector>

#include <osquery/plugin.h>

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

/// The running version of our database schema
extern const std::string kDatabaseResultsVersion;

/**
 * @brief The "domain" where buffered log results are stored.
 *
 * Logger plugins may shuttle logs to a remote endpoint or API call
 * asynchronously. The backing store can be used to buffer results and status
 * logs until the logger plugin-specific thread decided to flush.
 */
extern const std::string kLogs;

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

/**
 * @brief Allow the initializer to check the active database plugin.
 *
 * Unlink the initializer's Initializer::initActivePlugin helper method, the
 * database plugin should always be within the core. There is no need to
 * discover the active plugin via the registry or extensions API.
 *
 * The database should setUp in preparation for accesses.
 */
Status initializeDatabase();

void shutdownDatabase();
bool isDatabaseInitilized();

/// Allow callers to scan each column family and print each value.
void dumpDatabase();

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
Status upgradeDatabase();
} // namespace osquery
