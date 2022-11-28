/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <mutex>
#include <random>

#include <osquery/config/packs.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/version.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

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

std::once_flag kUseDenylist;

uint64_t splayValue(uint64_t original, uint64_t splayPercent) {
  if (splayPercent == 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  size_t possible_difference =
      static_cast<size_t>(original * percent_to_modify_by);
  uint64_t max_value = original + possible_difference;
  uint64_t min_value = std::max((uint64_t)1, original - possible_difference);

  if (max_value == min_value) {
    return max_value;
  }

  std::default_random_engine generator;
  generator.seed(static_cast<unsigned int>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<uint64_t> distribution(min_value, max_value);
  return distribution(generator);
}

size_t getMachineShard(const std::string& hostname = "", bool force = false) {
  static size_t shard = 0;
  if (shard > 0 && !force) {
    return shard;
  }

  // An optional input hostname may override hostname detection for testing.
  auto hn = (hostname.empty()) ? getHostname() : hostname;

  Hash hash(HASH_TYPE_SHA1);
  hash.update(hn.c_str(), hn.size());
  auto hn_hash = hash.digest();

  if (hn_hash.size() >= 2) {
    auto const hn_num = tryTo<long>(hn_hash.substr(0, 2), 16);
    if (hn_num.isValue()) {
      shard = (hn_num.get() * 100) / 255;
    }
  }
  return shard;
}

uint64_t restoreSplayedValue(const std::string& name, uint64_t interval) {
  // Attempt to restore a previously-calculated splay.
  std::string content;
  getDatabaseValue(kPersistentSettings, "interval." + name, content);
  if (!content.empty()) {
    // This query name existed before, check the last requested interval.
    auto details = osquery::split(content, ":");
    if (details.size() == 2) {
      auto const last_interval_exp = tryTo<long>(details[0], 10);
      auto const last_splay_exp = tryTo<long>(details[1], 10);
      if (last_interval_exp.isValue() && last_splay_exp.isValue()) {
        if (last_interval_exp.get() == static_cast<long>(interval) &&
            last_splay_exp.get() > 0) {
          // This is a matching interval, use the previous splay.
          return static_cast<size_t>(last_splay_exp.get());
        }
      }
    }
  }

  // If the splayed interval was not restored from the database.
  uint64_t splay = splayValue(interval, FLAGS_schedule_splay_percent);
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

  std::string oncall;
  if (obj.HasMember("oncall") && obj["oncall"].IsString()) {
    oncall = obj["oncall"].GetString();
  } else {
    oncall = "unknown";
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
      if (item.IsString()) {
        discovery_queries_.push_back(item.GetString());
      }
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
    VLOG(1) << "No queries defined for pack " << name;
    return;
  }

  // Iterate the queries (or schedule) and check platform/version/sanity.
  for (const auto& q : obj["queries"].GetObject()) {
    if (!q.value.IsObject() || !q.name.IsString()) {
      VLOG(1) << "The pack " << name << " contains an invalid query";
      continue;
    }

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
      VLOG(1) << "No query string defined for query " << q.name.GetString();
      continue;
    }

    ScheduledQuery query(
        name_, q.name.GetString(), q.value["query"].GetString());

    query.oncall = oncall;

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

    query.options["denylist"] = true;
    if (q.value.HasMember("denylist")) {
      query.options["denylist"] = JSON::valueToBool(q.value["denylist"]);
    }

    schedule_.emplace(std::make_pair(q.name.GetString(), std::move(query)));
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

bool Pack::checkPlatform() const {
  return checkPlatform(platform_);
}

bool Pack::checkPlatform(const std::string& platform) const {
  return ::osquery::checkPlatform(platform);
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
  uint64_t current = osquery::getUnixTime();
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
