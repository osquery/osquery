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

#include <osquery/plugin.h>

namespace osquery {

class Status;

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
                      size_t max) const;

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

 protected:
  /// The database was opened in a ReadOnly mode.
  bool read_only_{false};

  /// Original requested path on disk.
  std::string path_;
};

} // namespace osquery
