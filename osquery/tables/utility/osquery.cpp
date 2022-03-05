/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/config/packs.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/eventpublisher.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>
#include <osquery/utils/macros/macros.h>

namespace osquery {

DECLARE_bool(disable_logging);
DECLARE_bool(disable_events);

namespace tables {

QueryData genOsqueryEvents(QueryContext& context) {
  QueryData results;

  auto publishers = EventFactory::publisherTypes();
  for (const auto& publisher : publishers) {
    Row r;
    r["name"] = publisher;
    r["publisher"] = publisher;
    r["type"] = "publisher";

    auto pubref = EventFactory::getEventPublisher(publisher);
    if (pubref != nullptr) {
      r["subscriptions"] = INTEGER(pubref->numSubscriptions());
      r["events"] = INTEGER(pubref->numEvents());
      r["refreshes"] = INTEGER(pubref->restartCount());
      r["active"] = (pubref->hasStarted() && !pubref->isEnding()) ? "1" : "0";
    } else {
      r["subscriptions"] = "0";
      r["events"] = "0";
      r["refreshes"] = "0";
      r["active"] = "-1";
    }
    results.push_back(r);
  }

  auto subscribers = EventFactory::subscriberNames();
  for (const auto& subscriber : subscribers) {
    Row r;
    r["name"] = subscriber;
    r["type"] = "subscriber";
    // Subscribers will never 'restart'.
    r["refreshes"] = "0";

    auto subref = EventFactory::getEventSubscriber(subscriber);
    if (subref != nullptr) {
      r["publisher"] = subref->getType();
      r["subscriptions"] = INTEGER(subref->numSubscriptions());
      r["events"] = INTEGER(subref->numEvents());

      // Subscribers are always active, even if their publisher is not.
      r["active"] = (subref->state() == EventState::EVENT_RUNNING) ? "1" : "0";
    } else {
      r["subscriptions"] = "0";
      r["events"] = "0";
      r["active"] = "-1";
    }
    results.push_back(r);
  }

  return results;
}

QueryData genOsqueryPacks(QueryContext& context) {
  QueryData results;

  Config::get().packs([&results](const Pack& pack) {
    Row r;
    r["name"] = pack.getName();
    r["version"] = pack.getVersion();
    r["platform"] = pack.getPlatform();
    r["shard"] = INTEGER(pack.getShard());
    r["active"] = INTEGER(pack.isActive() ? 1 : 0);

    auto stats = pack.getStats();
    r["discovery_cache_hits"] = INTEGER(stats.hits);
    r["discovery_executions"] = INTEGER(stats.misses);
    results.push_back(r);
  });

  return results;
}

void genFlag(const std::string& name,
             const FlagInfo& flag,
             QueryData& results) {
  Row r;
  r["name"] = name;
  r["type"] = flag.type;
  r["description"] = flag.description;
  r["default_value"] = flag.default_value;
  r["value"] = flag.value;
  r["shell_only"] = (flag.detail.shell) ? "1" : "0";
  results.push_back(r);
}

QueryData genOsqueryFlags(QueryContext& context) {
  QueryData results;

  auto flags = Flag::flags();
  for (const auto& flag : flags) {
    if (flag.first.size() > 2) {
      // Skip single-character flags.
      genFlag(flag.first, flag.second, results);
    }
  }

  return results;
}

QueryData genOsqueryRegistry(QueryContext& context) {
  QueryData results;

  auto isActive = [](const std::string& plugin,
                     const RegistryInterfaceRef& registry) {
    if (FLAGS_disable_logging && registry->getName() == "logger") {
      return false;
    } else if (FLAGS_disable_events &&
               registry->getName().find("event") != std::string::npos) {
      return false;
    }

    const auto& active = registry->getActive();
    bool none_active = (active.empty());
    return (none_active || plugin == active);
  };

  auto& rf = RegistryFactory::get();
  for (const auto& registry_name : rf.names()) {
    // const auto& plugins = registry.second->all();
    const auto& plugins = rf.plugins(registry_name);
    auto registry = rf.registry(registry_name);
    for (const auto& plugin : plugins) {
      Row r;
      r["registry"] = registry_name;
      r["name"] = plugin.first;
      r["owner_uuid"] = "0";
      r["internal"] = (registry->isInternal(plugin.first)) ? "1" : "0";
      r["active"] = (isActive(plugin.first, registry)) ? "1" : "0";
      results.push_back(r);
    }

    for (const auto& route : registry->getExternal()) {
      Row r;
      r["registry"] = registry_name;
      r["name"] = route.first;
      r["owner_uuid"] = INTEGER(route.second);
      r["internal"] = "0";
      r["active"] = (isActive(route.first, registry)) ? "1" : "0";
      results.push_back(r);
    }
  }

  return results;
}

QueryData genOsqueryExtensions(QueryContext& context) {
  QueryData results;

  ExtensionList extensions;
  if (getExtensions(extensions).ok()) {
    for (const auto& extension : extensions) {
      Row r;
      r["uuid"] = SQL_TEXT(extension.first);
      r["name"] = extension.second.name;
      r["version"] = extension.second.version;
      r["sdk_version"] = extension.second.sdk_version;
      r["path"] = getExtensionSocket(extension.first);
      r["type"] = (extension.first == 0) ? "core" : "extension";
      results.push_back(r);
    }
  }

  return results;
}

QueryData genOsqueryInfo(QueryContext& context) {
  QueryData results;

  Row r;
  r["pid"] = INTEGER(PlatformProcess::getCurrentPid());
  r["version"] = kVersion;

  std::string hash_string;
  auto s = Config::get().genHash(hash_string);
  r["config_hash"] = (s.ok()) ? hash_string : "";
  r["config_valid"] = Config::get().isValid() ? INTEGER(1) : INTEGER(0);
  r["extensions"] =
      (pingExtension(FLAGS_extensions_socket).ok()) ? "active" : "inactive";
  r["build_platform"] = OSQUERY_BUILD_PLATFORM;
  r["build_distro"] = OSQUERY_BUILD_DISTRO;
  r["start_time"] = INTEGER(getStartTime());
  if (Initializer::isWorker()) {
    r["watcher"] = INTEGER(PlatformProcess::getLauncherProcess()->pid());
  } else {
    r["watcher"] = "-1";
  }
  r["platform_mask"] = INTEGER(static_cast<uint64_t>(kPlatformType));

  std::string uuid;
  r["uuid"] = (getHostUUID(uuid)) ? uuid : "";

  std::string instance;
  r["instance_id"] = (getInstanceUUID(instance)) ? instance : "";

  results.push_back(r);
  return results;
}

QueryData genOsquerySchedule(QueryContext& context) {
  QueryData results;

  Config::get().scheduledQueries(
      [&results](std::string name, const ScheduledQuery& query) {
        Row r;
        r["name"] = name;
        r["query"] = query.query;
        r["interval"] = INTEGER(query.interval);
        r["denylisted"] = (query.denylisted) ? "1" : "0";
        // Set default (0) values for each query if it has not yet executed.
        r["executions"] = "0";
        r["output_size"] = "0";
        r["wall_time"] = "0";
        r["wall_time_ms"] = "0";
        r["last_wall_time_ms"] = "0";
        r["user_time"] = "0";
        r["last_user_time"] = "0";
        r["system_time"] = "0";
        r["last_system_time"] = "0";
        r["average_memory"] = "0";
        r["last_memory"] = "0";
        r["last_executed"] = "0";

        // Report optional performance information.
        Config::get().getPerformanceStats(
            name, [&r](const QueryPerformance& perf) {
              r["executions"] = BIGINT(perf.executions);
              r["last_executed"] = BIGINT(perf.last_executed);
              r["output_size"] = BIGINT(perf.output_size);
              r["wall_time"] = BIGINT(perf.wall_time);
              r["wall_time_ms"] = BIGINT(perf.wall_time_ms);
              r["last_wall_time_ms"] = BIGINT(perf.last_wall_time_ms);
              r["user_time"] = BIGINT(perf.user_time);
              r["last_user_time"] = BIGINT(perf.last_user_time);
              r["system_time"] = BIGINT(perf.system_time);
              r["last_system_time"] = BIGINT(perf.last_system_time);
              r["average_memory"] = BIGINT(perf.average_memory);
              r["last_memory"] = BIGINT(perf.last_memory);
            });

        results.push_back(r);
      },
      true);
  return results;
}
} // namespace tables
} // namespace osquery
