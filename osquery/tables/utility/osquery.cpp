/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/extensions.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

typedef pt::ptree::value_type tree_node;

void genQueryPack(const tree_node& pack, QueryData& results) {
  Row r;
  // Packs are stored by name and contain configuration data.
  r["name"] = pack.first;
  r["path"] = pack.second.get("path", "");

  // There are optional restrictions on the set of queries applied pack-wide.
  auto pack_wide_version = pack.second.get("version", "");
  auto pack_wide_platform = pack.second.get("platform", "");

  // Iterate through each query in the pack.
  for (auto const& query : pack.second.get_child("queries")) {
    r["query_name"] = query.first;
    r["query"] = query.second.get("query", "");
    r["interval"] = INTEGER(query.second.get("interval", 0));
    r["description"] = query.second.get("description", "");
    r["value"] = query.second.get("value", "");

    // Set the version requirement based on the query-specific or pack-wide.
    if (query.second.count("version") > 0) {
      r["version"] = query.second.get("version", "");
    } else {
      r["version"] = pack_wide_platform;
    }

    // Set the platform requirement based on the query-specific or pack-wide.
    if (query.second.count("platform") > 0) {
      r["platform"] = query.second.get("platform", "");
    } else {
      r["platform"] = pack_wide_platform;
    }

    // Adding a prefix to the pack queries to differentiate packs from schedule.
    r["scheduled_name"] = "pack_" + r.at("name") + "_" + r.at("query_name");
    if (Config::checkScheduledQueryName(r.at("scheduled_name"))) {
      r["scheduled"] = INTEGER(1);
    } else {
      r["scheduled"] = INTEGER(0);
    }

    results.push_back(r);
  }
}

QueryData genOsqueryPacks(QueryContext& context) {
  QueryData results;

  // Get a lock on the config instance.
  ConfigDataInstance config;

  // Get the loaded data tree from global JSON configuration.
  const auto& packs_parsed_data = config.getParsedData("packs");

  // Iterate through all the packs to get each configuration and set of queries.
  for (auto const& pack : packs_parsed_data) {
    // Make sure the pack data contains queries.
    if (pack.second.count("queries") == 0) {
      continue;
    }
    genQueryPack(pack, results);
  }

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

  const auto& registries = RegistryFactory::all();
  for (const auto& registry : registries) {
    const auto& plugins = registry.second->all();
    for (const auto& plugin : plugins) {
      Row r;
      r["registry"] = registry.first;
      r["name"] = plugin.first;
      r["owner_uuid"] = "0";
      r["internal"] = (registry.second->isInternal(plugin.first)) ? "1" : "0";
      r["active"] = "1";
      results.push_back(r);
    }

    for (const auto& route : registry.second->getExternal()) {
      Row r;
      r["registry"] = registry.first;
      r["name"] = route.first;
      r["owner_uuid"] = INTEGER(route.second);
      r["internal"] = "0";
      r["active"] = "1";
      results.push_back(r);
    }
  }

  return results;
}

QueryData genOsqueryExtensions(QueryContext& context) {
  QueryData results;

  ExtensionList extensions;
  if (getExtensions(extensions).ok()) {
    for (const auto& extenion : extensions) {
      Row r;
      r["uuid"] = TEXT(extenion.first);
      r["name"] = extenion.second.name;
      r["version"] = extenion.second.version;
      r["sdk_version"] = extenion.second.sdk_version;
      r["path"] = getExtensionSocket(extenion.first);
      r["type"] = "extension";
      results.push_back(r);
    }
  }

  const auto& modules = RegistryFactory::getModules();
  for (const auto& module : modules) {
    Row r;
    r["uuid"] = TEXT(module.first);
    r["name"] = module.second.name;
    r["version"] = module.second.version;
    r["sdk_version"] = module.second.sdk_version;
    r["path"] = module.second.path;
    r["type"] = "module";
    results.push_back(r);
  }

  return results;
}

QueryData genOsqueryInfo(QueryContext& context) {
  QueryData results;

  Row r;
  r["pid"] = INTEGER(getpid());
  r["version"] = TEXT(OSQUERY_VERSION);

  std::string hash_string;
  auto s = Config::getMD5(hash_string);
  if (s.ok()) {
    r["config_md5"] = TEXT(hash_string);
  } else {
    r["config_md5"] = "";
    VLOG(1) << "Could not retrieve config hash: " << s.toString();
  }

  r["config_path"] = Flag::getValue("config_path");
  r["extensions"] =
      (pingExtension(FLAGS_extensions_socket).ok()) ? "active" : "inactive";

  r["build_platform"] = STR(OSQUERY_BUILD_PLATFORM);
  r["build_distro"] = STR(OSQUERY_BUILD_DISTRO);

  results.push_back(r);

  return results;
}

QueryData genOsquerySchedule(QueryContext& context) {
  QueryData results;

  ConfigDataInstance config;
  for (const auto& query : config.schedule()) {
    Row r;
    r["name"] = TEXT(query.first);
    r["query"] = TEXT(query.second.query);
    r["interval"] = INTEGER(query.second.interval);

    // Report optional performance information.
    r["executions"] = BIGINT(query.second.executions);
    r["output_size"] = BIGINT(query.second.output_size);
    r["wall_time"] = BIGINT(query.second.wall_time);
    r["user_time"] = BIGINT(query.second.user_time);
    r["system_time"] = BIGINT(query.second.system_time);
    r["average_memory"] = BIGINT(query.second.memory);
    results.push_back(r);
  }

  return results;
}

}
}
