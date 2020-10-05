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
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>

#include <boost/noncopyable.hpp>

#include <osquery/core/query.h>

#include <gtest/gtest_prod.h>

namespace osquery {

/// Statistics about Pack discovery query actions.
struct PackStats {
  size_t total{0};
  size_t hits{0};
  size_t misses{0};
};

/**
 * @brief The programmatic representation of a query pack
 */
class Pack : private boost::noncopyable {
 public:
  Pack(const std::string& name, const rapidjson::Value& obj)
      : Pack(name, "", obj) {}

  Pack(const std::string& name,
       const std::string& source,
       const rapidjson::Value& obj) {
    initialize(name, source, obj);
  }

  void initialize(const std::string& name,
                  const std::string& source,
                  const rapidjson::Value& obj);
  /**
   * @brief Getter for the pack's discovery query
   *
   * If the pack doesn't have a discovery query, false will be returned. If
   * the pack does have a discovery query, true will be returned and `query`
   * will be populated with the pack's discovery query
   *
   * @return A bool indicating whether or not the pack has a discovery query
   */
  const std::vector<std::string>& getDiscoveryQueries() const;

  /// Utility for identifying whether or not the pack should be scheduled
  bool shouldPackExecute();

  /// Returns the name of the pack
  const std::string& getName() const;

  /// Returns the name of the source from which the pack originated
  const std::string& getSource() const;

  /// Returns the platform that the pack is configured to run on
  const std::string& getPlatform() const;

  /// Returns the minimum version that the pack is configured to run on
  const std::string& getVersion() const;

  uint64_t getShard() const {
    return shard_;
  }

  /// Returns the schedule dictated by the pack
  const std::map<std::string, ScheduledQuery>& getSchedule() const;

  /// Returns the schedule dictated by the pack
  std::map<std::string, ScheduledQuery>& getSchedule();

  /// Verify that the platform is compatible
  bool checkPlatform() const;

  /// Verify that a given platform string is compatible
  bool checkPlatform(const std::string& platform) const;

  /// Verify that the version of osquery is compatible
  bool checkVersion() const;

  /// Verify that a given version string is compatible
  bool checkVersion(const std::string& version) const;

  /// Verify that a given discovery query returns the appropriate results
  bool checkDiscovery();

  /**
   * @brief Returns whether this pack is executing
   *
   * This can be used to determine whether the pack is active, without the
   * potential side effect of running the associated discovery queries.
   */
  bool isActive() const;

  const PackStats& getStats() const;

 protected:
  /// List of query strings.
  std::vector<std::string> discovery_queries_;

  /// Map of query names to the scheduled query details.
  std::map<std::string, ScheduledQuery> schedule_;

  /// Platform requirement for pack.
  std::string platform_;

  /// Minimum version requirement for pack.
  std::string version_;

  /// Optional shard requirement for pack.
  uint64_t shard_{0};

  /// Pack canonicalized name.
  std::string name_;

  /// Name of config source that created/added this pack.
  std::string source_;

  /// Cached time and result from previous discovery step.
  std::pair<uint64_t, bool> discovery_cache_;

  /// Aggregate appropriateness of pack for this host.
  std::atomic<bool> valid_{false};

  /// Whether this pack is active (valid_ && checkDiscovery())
  std::atomic<bool> active_{false};

  /// Pack discovery statistics.
  PackStats stats_;

 private:
  /**
   * @brief Private default constructor
   *
   * Initialization must include pack content
   */
  Pack() {}

 private:
  FRIEND_TEST(PacksTests, test_check_platform);
};

/**
 * @brief Generate a splayed interval.
 *
 * The osquery schedule and packs take an approximate interval for each query.
 * The config option "schedule_splay_percent" is used to adjust the interval,
 * the result "splayed_interval" could be adjusted to be sooner or later.
 *
 * @param original the original positive interval in seconds.
 * @param splay_percent a positive percent (1-100) to splay.
 * @return the result splayed value.
 */
uint64_t splayValue(uint64_t original, uint64_t splay_percent);

/**
 * @brief Retrieve a previously-calculated splay for a name/interval pair.
 *
 * To provide consistency and determinism to schedule executions, splays can
 * be cached in the database. If a query name (or pack-generated name) and its
 * interval remain the same then a cached splay can be used.
 *
 * If a "cache miss" occurs, a new splay for the name and interval pair is
 * generated and saved.
 *
 * @param name the generated query name.
 * @param interval the requested pre-splayed interval.
 * @return either the restored previous calculated splay, or a new splay.
 */
uint64_t restoreSplayedValue(const std::string& name, uint64_t interval);
} // namespace osquery
