/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <random>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/packs.h>
#include <osquery/sql.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(int32,
     pack_refresh_interval,
     3600,
     "Cache expiration for a packs discovery queries");

FLAG(int32, schedule_splay_percent, 10, "Percent to splay config times");

FLAG(int32,
     schedule_default_interval,
     3600,
     "Query interval to use if none is provided");

size_t splayValue(size_t original, size_t splayPercent) {
  if (splayPercent <= 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  size_t possible_difference = original * percent_to_modify_by;
  size_t max_value = original + possible_difference;
  size_t min_value = std::max((size_t)1, original - possible_difference);

  if (max_value == min_value) {
    return max_value;
  }

  std::default_random_engine generator;
  generator.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<size_t> distribution(min_value, max_value);
  return distribution(generator);
}

size_t restoreSplayedValue(const std::string& name, size_t interval) {
  // Attempt to restore a previously-calculated splay.
  std::string content;
  getDatabaseValue(kPersistentSettings, "interval." + name, content);
  if (!content.empty()) {
    // This query name existed before, check the last requested interval.
    auto details = osquery::split(content, ":");
    if (details.size() == 2) {
      long last_interval, last_splay;
      if (safeStrtol(details[0], 10, last_interval) &&
          safeStrtol(details[1], 10, last_splay)) {
        if (last_interval == static_cast<long>(interval) && last_splay > 0) {
          // This is a matching interval, use the previous splay.
          return static_cast<size_t>(last_splay);
        }
      }
    }
  }

  // If the splayed interval was not restored from the database.
  auto splay = splayValue(interval, FLAGS_schedule_splay_percent);
  content = std::to_string(interval) + ":" + std::to_string(splay);
  setDatabaseValue(kPersistentSettings, "interval." + name, content);
  return splay;
}

void Pack::initialize(const std::string& name,
                      const std::string& source,
                      const pt::ptree& tree) {
  name_ = name;
  source_ = source;
  discovery_queries_.clear();
  if (tree.count("discovery") > 0) {
    for (const auto& item : tree.get_child("discovery")) {
      discovery_queries_.push_back(item.second.get_value<std::string>());
    }
  }

  discovery_cache_ = std::make_pair<int, bool>(0, false);
  stats_ = {0, 0, 0};

  platform_.clear();
  if (tree.count("platform") > 0) {
    platform_ = tree.get<std::string>("platform", "");
  }

  version_.clear();
  if (tree.count("version") > 0) {
    version_ = tree.get<std::string>("version", "");
  }

  schedule_.clear();
  if (tree.count("queries") == 0) {
    // This pack contained no queries.
    return;
  }

  // If the splay percent is less than 1 reset to a sane estimate.
  if (FLAGS_schedule_splay_percent <= 1) {
    FLAGS_schedule_splay_percent = 10;
  }

  // Iterate the queries (or schedule) and check platform/version/sanity.
  for (const auto& q : tree.get_child("queries")) {
    if (q.second.count("platform")) {
      if (!checkPlatform(q.second.get<std::string>("platform", ""))) {
        continue;
      }
    }

    if (q.second.count("version")) {
      if (!checkVersion(q.second.get<std::string>("version", ""))) {
        continue;
      }
    }

    ScheduledQuery query;
    query.query = q.second.get<std::string>("query", "");
    query.interval = q.second.get("interval", FLAGS_schedule_default_interval);
    if (query.interval <= 0 || query.query.empty()) {
      // Invalid pack query.
      continue;
    }

    query.splayed_interval = restoreSplayedValue(q.first, query.interval);
    query.options["snapshot"] = q.second.get<bool>("snapshot", false);
    query.options["removed"] = q.second.get<bool>("removed", true);
    schedule_[q.first] = query;
  }
}

const std::map<std::string, ScheduledQuery>& Pack::getSchedule() const {
  return schedule_;
}

const std::vector<std::string>& Pack::getDiscoveryQueries() const {
  return discovery_queries_;
}

const PackStats& Pack::getStats() const { return stats_; }

const std::string& Pack::getPlatform() const { return platform_; }

const std::string& Pack::getVersion() const { return version_; }

bool Pack::shouldPackExecute() {
  return checkVersion() && checkPlatform() && checkDiscovery();
}

const std::string& Pack::getName() const { return name_; }

const std::string& Pack::getSource() const { return source_; }

void Pack::setName(const std::string& name) { name_ = name; }

bool Pack::checkPlatform() const { return checkPlatform(platform_); }

bool Pack::checkPlatform(const std::string& platform) const {
  if (platform == "") {
    return true;
  }

#ifdef __linux__
  if (platform.find("linux") != std::string::npos) {
    return true;
  }
#endif

  if (platform.find("any") != std::string::npos ||
      platform.find("all") != std::string::npos) {
    return true;
  }
  return (platform.find(kSDKPlatform) != std::string::npos);
}

bool Pack::checkVersion() const { return checkVersion(version_); }

bool Pack::checkVersion(const std::string& version) const {
  if (version == "") {
    return true;
  }

  auto required_version = split(version, ".");
  auto build_version = split(kSDKVersion, ".");

  size_t index = 0;
  for (const auto& chunk : build_version) {
    if (required_version.size() <= index) {
      return true;
    }
    try {
      if (std::stoi(chunk) < std::stoi(required_version[index])) {
        return false;
      } else if (std::stoi(chunk) > std::stoi(required_version[index])) {
        return true;
      }
    } catch (const std::invalid_argument& e) {
      if (chunk.compare(required_version[index]) < 0) {
        return false;
      }
    }
    index++;
  }
  return true;
}

bool Pack::checkDiscovery() {
  stats_.total++;
  int current = (int)getUnixTime();
  if ((current - discovery_cache_.first) < FLAGS_pack_refresh_interval) {
    stats_.hits++;
    return discovery_cache_.second;
  }

  stats_.misses++;
  discovery_cache_.first = current;
  discovery_cache_.second = true;
  for (const auto& q : discovery_queries_) {
    auto sql = SQL(q);
    if (!sql.ok()) {
      LOG(WARNING) << "Discovery query failed (" << q
                   << "): " << sql.getMessageString();
      discovery_cache_.second = false;
      break;
    }
    if (sql.rows().size() == 0) {
      discovery_cache_.second = false;
      break;
    }
  }
  return discovery_cache_.second;
}
}
