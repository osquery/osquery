/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/json/json.h>
#include <plugins/config/parsers/decorators.h>

namespace osquery {

FLAG(bool, disable_decorators, false, "Disable log result decoration");

FLAG(bool,
     decorations_top_level,
     false,
     "Add decorators as top level JSON object members");

/// Statically define the parser name to avoid mistakes.
const std::string kDecorationsName{"decorators"};

const std::map<DecorationPoint, std::string> kDecorationPointKeys = {
    {DECORATE_LOAD, "load"},
    {DECORATE_ALWAYS, "always"},
    {DECORATE_INTERVAL, "interval"},
};

using KeyValueMap = std::map<std::string, std::string>;
using DecorationStore = std::map<std::string, KeyValueMap>;

namespace {

/**
 * @brief A simple ConfigParserPlugin for a "decorators" dictionary key.
 *
 * Decorators append data to results, snapshots, and status log lines.
 * They can be used to add arbitrary additional datums within the 'decorators'
 * subkey.
 *
 * Decorators come in three basic flavors, defined by when they are run:
 * load: run these decorators when the config is loaded.
 * always: run these decorators for every query immediate before
 * interval: run these decorators on an interval.
 *
 * When 'interval' is used, the value is a dictionary of intervals, each of the
 * subkeys are treated as the requested interval in sections. The internals
 * are emulated by the query schedule.
 *
 * Decorators are sets of queries, and each selected column within the set is
 * added to the 'decorators' dictionary. Including two queries with the same
 * column name is undefined behavior and will most likely lead to either
 * duplicate keys or overwriting. Issuing a query that emits more than one row
 * will also lead to undefined behavior. The decorator executor will ignore any
 * rows past the first.
 */
class DecoratorsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {kDecorationsName};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;

  /// Run the load decorators of the sources that update() received.
  void afterUpdate() override;

  /// Update the set of decorators for a given source.
  void updateDecorations(const std::string& source, const JSON& doc);

  /// Clear the decorations created from decorators for the given source.
  void clearSources(const std::string& source);

  /// Clear all decorations.
  virtual void reset() override;

 public:
  /// Set of configuration sources to the set of decorator queries.
  std::map<std::string, std::vector<std::string>> always_;

  /// Set of configuration sources to the set of on-load decorator queries.
  std::map<std::string, std::vector<std::string>> load_;

  /// Set of configuration sources to valid intervals.
  std::map<std::string, std::map<uint64_t, std::vector<std::string>>>
      intervals_;

 public:
  /// The result set of decorations, column names and their values.
  static DecorationStore kDecorations;

  /// Protect additions to the decorator set.
  static Mutex kDecorationsMutex;

  /// Protect the configuration controlled content.
  static Mutex kDecorationsConfigMutex;

  /// The generation of each source's decorators, which changes whenever they
  /// are replaced. Results of queries from a replaced set of decorators are
  /// not published. Protected by kDecorationsConfigMutex.
  static std::map<std::string, uint64_t> kDecorationGenerations;
};

/// The sources, and their decorator generations, whose load decorators
/// update() left for afterUpdate() to run. It is per-thread like the config's
/// pending parsers, so each config update runs its own load decorators.
thread_local std::vector<std::pair<std::string, uint64_t>>
    kPendingLoadDecorators;

/// The generation of a source's decorators. kDecorationsConfigMutex must be
/// held.
uint64_t decorationGeneration(const std::string& source) {
  auto generation =
      DecoratorsConfigParserPlugin::kDecorationGenerations.find(source);
  return generation ==
                 DecoratorsConfigParserPlugin::kDecorationGenerations.end()
             ? 0
             : generation->second;
}
} // namespace

DecorationStore DecoratorsConfigParserPlugin::kDecorations;
Mutex DecoratorsConfigParserPlugin::kDecorationsMutex;
Mutex DecoratorsConfigParserPlugin::kDecorationsConfigMutex;
std::map<std::string, uint64_t>
    DecoratorsConfigParserPlugin::kDecorationGenerations;

static void runDecorators(const std::string& source,
                          uint64_t generation,
                          const std::vector<std::string>& queries);

Status DecoratorsConfigParserPlugin::setUp() {
  // Decorators are kept within customized data structures.
  // No need to define a key for the ::getData API.
  return Status(0, "OK");
}

Status DecoratorsConfigParserPlugin::update(const std::string& source,
                                            const ParserConfig& config) {
  clearSources(source);
  clearDecorations(source);
  auto decorations = config.find(kDecorationsName);
  if (decorations != config.end()) {
    if (!decorations->second.doc().IsObject()) {
      const auto error_message =
          "Invalid format for decorators configuration, decorators value "
          "must be a JSON "
          "object";
      LOG(WARNING) << error_message;

      return Status::failure(error_message);
    }

    // Each of these methods acquires the decorator lock separately.
    // The run decorators method is designed to have call sites throughout
    // the code base.
    updateDecorations(source, decorations->second);

    // Load decorators may query tables, such as ATC tables, that parsers
    // attach in afterUpdate(), so they run in afterUpdate() too.
    ReadLock lock(kDecorationsConfigMutex);
    kPendingLoadDecorators.emplace_back(source, decorationGeneration(source));
  }

  auto doc = JSON::newObject();
  doc.copyFrom(data_.doc());
  data_ = std::move(doc);

  return Status(0, "OK");
}

void DecoratorsConfigParserPlugin::afterUpdate() {
  std::vector<std::pair<std::string, uint64_t>> loads;
  loads.swap(kPendingLoadDecorators);
  if (FLAGS_disable_decorators) {
    return;
  }

  for (const auto& load : loads) {
    std::vector<std::string> queries;
    {
      ReadLock lock(kDecorationsConfigMutex);
      if (decorationGeneration(load.first) != load.second) {
        // A newer update replaced these decorators. It runs its own once its
        // changes, such as new ATC tables, have been applied.
        continue;
      }
      auto source_queries = load_.find(load.first);
      if (source_queries != load_.end()) {
        queries = source_queries->second;
      }
    }
    runDecorators(load.first, load.second, queries);
  }
}

void DecoratorsConfigParserPlugin::clearSources(const std::string& source) {
  // Reset the internal data store.
  WriteLock lock(DecoratorsConfigParserPlugin::kDecorationsConfigMutex);
  kDecorationGenerations[source]++;
  if (intervals_.count(source) > 0) {
    intervals_[source].clear();
  }

  if (always_.count(source) > 0) {
    always_[source].clear();
  }

  if (load_.count(source) > 0) {
    load_[source].clear();
  }
}

void DecoratorsConfigParserPlugin::reset() {
  // Reset the internal data store (for all sources).
  for (const auto& source : DecoratorsConfigParserPlugin::kDecorations) {
    clearSources(source.first);
    clearDecorations(source.first);
  }
}

void DecoratorsConfigParserPlugin::updateDecorations(const std::string& source,
                                                     const JSON& doc) {
  WriteLock lock(DecoratorsConfigParserPlugin::kDecorationsConfigMutex);
  // Assign load decorators.
  auto& load_key = kDecorationPointKeys.at(DECORATE_LOAD);
  if (doc.doc().HasMember(load_key)) {
    auto& load = doc.doc()[load_key];
    if (load.IsArray()) {
      for (const auto& item : load.GetArray()) {
        if (item.IsString()) {
          load_[source].push_back(item.GetString());
        }
      }
    }
  }

  // Assign always decorators.
  auto& always_key = kDecorationPointKeys.at(DECORATE_ALWAYS);
  if (doc.doc().HasMember(always_key)) {
    auto& always = doc.doc()[always_key];
    if (always.IsArray()) {
      for (const auto& item : always.GetArray()) {
        if (item.IsString()) {
          always_[source].push_back(item.GetString());
        }
      }
    }
  }

  // Check if intervals are defined.
  auto& interval_key = kDecorationPointKeys.at(DECORATE_INTERVAL);
  if (!doc.doc().HasMember(interval_key)) {
    return;
  }

  const auto& interval = doc.doc()[interval_key];
  if (!interval.IsObject()) {
    LOG(WARNING)
        << "Invalid decorator interval configuration in config source: "
        << source;
    return;
  }

  for (const auto& item : interval.GetObject()) {
    auto rate = doc.valueToSize(item.name);
    //      size_t rate = std::stoll(item.name.GetString());
    if (rate % 60 != 0) {
      LOG(WARNING) << "Invalid decorator interval rate " << rate
                   << " in config source: " << source;
      continue;
    }

    if (!item.value.IsArray()) {
      LOG(WARNING) << "Invalid decorator interval rate " << rate
                   << " configuration in config source: " << source;
      continue;
    }

    // This is a valid interval, update the set of intervals to include
    // this value. When intervals are checked this set is scanned, if a
    // match is found, then the associated config data is executed.
    for (const auto& interval_query : item.value.GetArray()) {
      if (interval_query.IsString()) {
        intervals_[source][rate].push_back(interval_query.GetString());
      }
    }
  }
}

/// Publish a decorator query's result, unless its decorators were replaced.
inline void addDecorations(const std::string& source,
                           uint64_t generation,
                           const Row& row) {
  ReadLock config_lock(DecoratorsConfigParserPlugin::kDecorationsConfigMutex);
  if (decorationGeneration(source) != generation) {
    return;
  }

  WriteLock lock(DecoratorsConfigParserPlugin::kDecorationsMutex);
  for (const auto& column : row) {
    DecoratorsConfigParserPlugin::kDecorations[source][column.first] =
        column.second;
  }
}

/**
 * Run decorator queries and publish their results.
 *
 * No decorator lock may be held: the queries can read tables, such as
 * osquery_schedule, that take config locks, while a config update holding those
 * locks waits for the decorator locks.
 */
static void runDecorators(const std::string& source,
                          uint64_t generation,
                          const std::vector<std::string>& queries) {
#ifdef OSQUERY_IS_FUZZING
  return;
#else

  for (const auto& query : queries) {
    SQL results(query);
    if (results.rows().size() > 0) {
      // Notice the warning below about undefined behavior when:
      // 1: You include decorators that emit the same column name
      // 2: You include a query that returns more than 1 row.
      addDecorations(source, generation, results.rows()[0]);
    }

    if (results.rows().size() > 1) {
      // Multiple rows exhibit undefined behavior.
      LOG(WARNING) << "Multiple rows returned for decorator query: " << query;
    }
  }
#endif
}

void clearDecorations(const std::string& source) {
  WriteLock lock(DecoratorsConfigParserPlugin::kDecorationsMutex);
  DecoratorsConfigParserPlugin::kDecorations[source].clear();
}

void runDecorators(DecorationPoint point,
                   uint64_t time,
                   const std::string& source) {
  if (FLAGS_disable_decorators) {
    return;
  }

  auto parser = Config::getParser(kDecorationsName);
  if (parser == nullptr) {
    // The decorators parser does not exist.
    return;
  }

  // Copy the queries to run, then run them without holding the lock.
  std::vector<std::tuple<std::string, uint64_t, std::vector<std::string>>> runs;
  {
    // Abstract the use of the decorator parser API.
    ReadLock lock(DecoratorsConfigParserPlugin::kDecorationsConfigMutex);
    auto dp = std::dynamic_pointer_cast<DecoratorsConfigParserPlugin>(parser);
    auto addRun = [&runs](const std::string& target_source,
                          const std::vector<std::string>& queries) {
      runs.emplace_back(
          target_source, decorationGeneration(target_source), queries);
    };
    if (point == DECORATE_LOAD) {
      for (const auto& target_source : dp->load_) {
        if (source.empty() || target_source.first == source) {
          addRun(target_source.first, target_source.second);
        }
      }
    } else if (point == DECORATE_ALWAYS) {
      for (const auto& target_source : dp->always_) {
        if (source.empty() || target_source.first == source) {
          addRun(target_source.first, target_source.second);
        }
      }
    } else if (point == DECORATE_INTERVAL) {
      for (const auto& target_source : dp->intervals_) {
        for (const auto& interval : target_source.second) {
          if (time % interval.first == 0) {
            if (source.empty() || target_source.first == source) {
              addRun(target_source.first, interval.second);
            }
          }
        }
      }
    }
  }

  for (const auto& run : runs) {
    runDecorators(std::get<0>(run), std::get<1>(run), std::get<2>(run));
  }
}

void getDecorations(std::map<std::string, std::string>& results) {
  if (FLAGS_disable_decorators) {
    return;
  }

  ReadLock lock(DecoratorsConfigParserPlugin::kDecorationsMutex);
  // Copy the decorations into the log_item.
  for (const auto& source : DecoratorsConfigParserPlugin::kDecorations) {
    for (const auto& decoration : source.second) {
      results[decoration.first] = decoration.second;
    }
  }
}

REGISTER_INTERNAL(DecoratorsConfigParserPlugin,
                  "config_parser",
                  kDecorationsName.c_str());
} // namespace osquery
