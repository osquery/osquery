/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <algorithm>
#include <random>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/packs.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace rj = rapidjson;

namespace osquery {

FLAG(uint64,
     pack_refresh_interval,
     3600,
     "Cache expiration for a packs discovery queries");

FLAG(string, pack_delimiter, "_", "Delimiter for pack and query names");

FLAG(uint64, schedule_splay_percent, 10, "Percent to splay config times");

FLAG(uint64,
     schedule_default_interval,
     3600,
     "Query interval to use if none is provided");

size_t kMaxQueryInterval = 604800;

size_t splayValue(size_t original, size_t splayPercent) {
  if (splayPercent == 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  size_t possible_difference =
      static_cast<size_t>(original * percent_to_modify_by);
  size_t max_value = original + possible_difference;
  size_t min_value = std::max((size_t)1, original - possible_difference);

  if (max_value == min_value) {
    return max_value;
  }

  std::default_random_engine generator;
  generator.seed(static_cast<unsigned int>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<size_t> distribution(min_value, max_value);
  return distribution(generator);
}

size_t getMachineShard(const std::string& hostname = "", bool force = false) {
  static size_t shard = 0;
  if (shard > 0 && !force) {
    return shard;
  }

  // An optional input hostname may override hostname detection for testing.
  auto hn = (hostname.empty()) ? getHostname() : hostname;
  auto hn_hash = getBufferSHA1(hn.c_str(), hn.size());

  if (hn_hash.size() >= 2) {
    long hn_char;
    if (safeStrtol(hn_hash.substr(0, 2), 16, hn_char)) {
      shard = (hn_char * 100) / 255;
    }
  }
  return shard;
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
                      const rj::Value& obj) {
  name_ = name;
  source_ = source;
  // Check the shard limitation, shards falling below this value are included.
  if (obj.HasMember("shard")) {
    shard_ = JSON::valueToSize(obj["shard"]);
  }

  // Check for a platform restriction.
  platform_.clear();
  if (obj.HasMember("platform") && obj["platform"].IsString()) {
    platform_ = obj["platform"].GetString();
  }

  // Check for a version restriction.
  version_.clear();
  if (obj.HasMember("version") && obj["version"].IsString()) {
    version_ = obj["version"].GetString();
  }

  // Apply the shard, platform, and version checking.
  // It is important to set each value such that the packs meta-table can report
  // each of the restrictions.
  if ((shard_ > 0 && shard_ < getMachineShard()) || !checkPlatform() ||
      !checkVersion()) {
    return;
  }

  discovery_queries_.clear();
  if (obj.HasMember("discovery") && obj["discovery"].IsArray()) {
    for (const auto& item : obj["discovery"].GetArray()) {
      discovery_queries_.push_back(item.GetString());
    }
  }

  // Initialize a discovery cache at time 0.
  discovery_cache_ = std::make_pair<size_t, bool>(0, false);
  valid_ = true;

  // If the splay percent is less than 1 reset to a sane estimate.
  if (FLAGS_schedule_splay_percent <= 1) {
    FLAGS_schedule_splay_percent = 10;
  }

  schedule_.clear();
  if (!obj.HasMember("queries") || !obj["queries"].IsObject()) {
    // This pack contained no queries.
    return;
  }

  // Iterate the queries (or schedule) and check platform/version/sanity.
  for (const auto& q : obj["queries"].GetObject()) {
    if (q.value.HasMember("shard")) {
      auto shard = JSON::valueToSize(q.value["shard"]);
      if (shard > 0 && shard < getMachineShard()) {
        continue;
      }
    }

    if (q.value.HasMember("platform") && q.value["platform"].IsString()) {
      if (!checkPlatform(q.value["platform"].GetString())) {
        continue;
      }
    }

    if (q.value.HasMember("version") && q.value["version"].IsString()) {
      if (!checkVersion(q.value["version"].GetString())) {
        continue;
      }
    }

    if (!q.value.HasMember("query") || !q.value["query"].IsString()) {
      continue;
    }

    ScheduledQuery query;
    query.query = q.value["query"].GetString();
    if (!q.value.HasMember("interval")) {
      query.interval = FLAGS_schedule_default_interval;
    } else {
      query.interval = JSON::valueToSize(q.value["interval"]);
    }
    if (query.interval <= 0 || query.query.empty() ||
        query.interval > kMaxQueryInterval) {
      // Invalid pack query.
      LOG(WARNING) << "Query has invalid interval: " << q.name.GetString()
                   << ": " << query.interval;
      continue;
    }

    query.splayed_interval =
        restoreSplayedValue(q.name.GetString(), query.interval);

    if (!q.value.HasMember("snapshot")) {
      query.options["snapshot"] = false;
    } else {
      query.options["snapshot"] = JSON::valueToBool(q.value["snapshot"]);
    }

    if (!q.value.HasMember("removed")) {
      query.options["removed"] = true;
    } else {
      query.options["removed"] = JSON::valueToBool(q.value["removed"]);
    }
    query.options["blacklist"] = (q.value.HasMember("blacklist"))
                                     ? q.value["blacklist"].GetBool()
                                     : true;

    schedule_[q.name.GetString()] = query;
  }
}

const std::map<std::string, ScheduledQuery>& Pack::getSchedule() const {
  return schedule_;
}

std::map<std::string, ScheduledQuery>& Pack::getSchedule() {
  return schedule_;
}

const std::vector<std::string>& Pack::getDiscoveryQueries() const {
  return discovery_queries_;
}

const PackStats& Pack::getStats() const {
  return stats_;
}

const std::string& Pack::getPlatform() const {
  return platform_;
}

const std::string& Pack::getVersion() const {
  return version_;
}

bool Pack::shouldPackExecute() {
  active_ = (valid_ && checkDiscovery());
  return active_;
}

const std::string& Pack::getName() const {
  return name_;
}

const std::string& Pack::getSource() const {
  return source_;
}

void Pack::setName(const std::string& name) {
  name_ = name;
}

bool Pack::checkPlatform() const {
  return checkPlatform(platform_);
}

bool Pack::checkPlatform(const std::string& platform) const {
  if (platform.empty() || platform == "null") {
    return true;
  }

  if (platform.find("any") != std::string::npos ||
      platform.find("all") != std::string::npos) {
    return true;
  }

  auto linux_type = (platform.find("linux") != std::string::npos ||
                     platform.find("ubuntu") != std::string::npos ||
                     platform.find("centos") != std::string::npos);
  if (linux_type && isPlatform(PlatformType::TYPE_LINUX)) {
    return true;
  }

  auto posix_type = (platform.find("posix") != std::string::npos);
  if (posix_type && isPlatform(PlatformType::TYPE_POSIX)) {
    return true;
  }

  return (platform.find(kSDKPlatform) != std::string::npos);
}

bool Pack::checkVersion() const {
  return checkVersion(version_);
}

bool Pack::checkVersion(const std::string& version) const {
  if (version.empty() || version == "null") {
    return true;
  }

  return versionAtLeast(version, kSDKVersion);
}

bool Pack::checkDiscovery() {
  stats_.total++;
  size_t current = osquery::getUnixTime();
  if ((current - discovery_cache_.first) < FLAGS_pack_refresh_interval) {
    stats_.hits++;
    return discovery_cache_.second;
  }

  stats_.misses++;
  discovery_cache_.first = current;
  discovery_cache_.second = true;
  for (const auto& q : discovery_queries_) {
    SQL results(q);
    if (!results.ok()) {
      LOG(WARNING) << "Discovery query failed (" << q
                   << "): " << results.getMessageString();
      discovery_cache_.second = false;
      break;
    }
    if (results.rows().size() == 0) {
      discovery_cache_.second = false;
      break;
    }
  }
  return discovery_cache_.second;
}

bool Pack::isActive() const {
  return active_;
}
}
