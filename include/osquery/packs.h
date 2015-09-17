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
#include <utility>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/database.h>
#include <osquery/status.h>

namespace osquery {

typedef struct {
  int total;
  int hits;
  int misses;
} PackStats;

/**
 * @brief The programatic representation of a query pack
 *
 * Instantiating a new Pack object parses JSON and may throw a
 * boost::property_tree::json_parser::json_parser_error exception
 */
class Pack {
 public:
  Pack(const std::string& name, const boost::property_tree::ptree& tree);
  Pack(const std::string& name, const std::string& json);
  Pack(const std::string& name,
       const std::string& source,
       const boost::property_tree::ptree& tree);
  Pack(const std::string& name,
       const std::string& source,
       const std::string& json);

  void initialize(const std::string& name,
                  const std::string& source,
                  const boost::property_tree::ptree& tree);
  /**
   * @brief Getter for the pack's discovery query
   *
   * If the pack doesn't have a discovery query, false will be returned. If
   * the pack does have a discovery query, true will be returned and `query`
   * will be populated with the pack's discovery query
   *
   * @return A bool indicating whether or not the pack has a discovery query
   */
  std::vector<std::string>& getDiscoveryQueries();

  /// Utility for identifying whether or not the pack should be scheduled
  bool shouldPackExecute();

  /// Sets the name of the pack
  void setName(const std::string& name);

  /// Returns the name of the pack
  const std::string& getName() const;

  /// Returns the name of the source from which the pack originated
  const std::string& getSource() const;

  /// Returns the platform that the pack is configured to run on
  const std::string& getPlatform() const;

  /// Returns the minimum version that the pack is configured to run on
  const std::string& getVersion() const;

  /// Returns the schedule dictated by the pack
  const std::map<std::string, ScheduledQuery>& getSchedule();

  /// Verify that the platform is compatible
  bool checkPlatform();

  /// Verify that a given platform string is compatible
  bool checkPlatform(const std::string& platform);

  /// Verify that the version of osquery is compatible
  bool checkVersion();

  /// Verify that a given version string is compatible
  bool checkVersion(const std::string& version);

  /// Verify that a given discovery query returns the appropriate results
  bool checkDiscovery();

  const PackStats& getStats();

 protected:
  std::vector<std::string> discovery_queries_;
  std::map<std::string, ScheduledQuery> schedule_;
  std::string platform_;
  std::string version_;
  std::string name_;
  std::string source_;
  bool should_execute_;
  std::pair<int, bool> discovery_cache_;
  PackStats stats_;

 private:
  /**
   * @brief Private default constructor
   *
   * Initialization must include pack content
   */
  Pack(){};
};
}
