/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <random>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/packs.h>
#include <osquery/sql.h>

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_int32(schedule_splay_percent);

FLAG(int32,
     pack_refresh_interval,
     3600,
     "Cache expiration for a packs discovery queries");

FLAG(int32,
     schedule_default_interval,
     3600,
     "Query interval to use if none is provided");

Pack::Pack(const std::string& name, const pt::ptree& tree) {
  initialize(name, "", tree);
}

Pack::Pack(const std::string& name,
           const std::string& source,
           const pt::ptree& tree) {
  initialize(name, source, tree);
}

Pack::Pack(const std::string& name, const std::string& json) {
  std::stringstream stream;
  stream << json;
  pt::ptree tree;
  try {
    pt::read_json(stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    LOG(ERROR) << "Error parsing pack JSON. Re-throwing the exception.";
    throw;
  }
  initialize(name, "", tree);
}

Pack::Pack(const std::string& name,
           const std::string& source,
           const std::string& json) {
  std::stringstream stream;
  stream << json;
  pt::ptree tree;
  try {
    pt::read_json(stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    LOG(ERROR) << "Error parsing pack JSON. Re-throwing the exception.";
    throw;
  }
  initialize(name, source, tree);
}

int splayValue(int original, int splayPercent) {
  if (splayPercent <= 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  int possible_difference = original * percent_to_modify_by;
  int max_value = original + possible_difference;
  int min_value = original - possible_difference;

  if (max_value == min_value) {
    return max_value;
  }

  std::default_random_engine generator;
  generator.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<int> distribution(min_value, max_value);
  return distribution(generator);
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
    platform_ = tree.get<std::string>("platform");
  }

  version_.clear();
  if (tree.count("version") > 0) {
    version_ = tree.get<std::string>("version");
  }

  schedule_.clear();
  if (tree.count("queries") > 0) {
    for (const auto& q : tree.get_child("queries")) {
      if (q.second.count("platform")) {
        if (!checkPlatform(q.second.get<std::string>("platform"))) {
          continue;
        }
      }

      if (q.second.count("version")) {
        if (!checkVersion(q.second.get<std::string>("version"))) {
          continue;
        }
      }

      ScheduledQuery query;
      query.interval =
          q.second.get<int>("interval", FLAGS_schedule_default_interval);
      query.splayed_interval =
          splayValue(query.interval, FLAGS_schedule_splay_percent);
      query.query = q.second.get<std::string>("query");
      query.options["snapshot"] = q.second.get<bool>("snapshot", false);
      query.options["removed"] = q.second.get<bool>("removed", true);
      schedule_[q.first] = query;
    }
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
  auto current = getUnixTime();
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
