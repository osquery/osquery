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

#include "osquery/config/parsers/query_packs.h"

namespace osquery {
namespace tables {

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

QueryData genOsqueryPacks(QueryContext& context) {
  Row r;
  QueryData results;
  ConfigDataInstance config;

  // Get the instance for the parser
  const auto& pack_parser = config.getParser("packs");
  if (pack_parser == nullptr) {
    return results;
  }
  const auto& queryPackParser = std::static_pointer_cast<QueryPackConfigParserPlugin>(pack_parser);
  if (queryPackParser == nullptr) {
    return results;
  }

  // Get the loaded data tree from global JSON configuration
  const auto& packs_parsed_data = config.getParsedData("packs");
  if (packs_parsed_data.count("packs") == 0) {
    return results;
  }

  // Iterate through all the packs to get the configuration
  for(auto const &pack_element : packs_parsed_data) {
    // Make sure the element has items
    if (pack_element.second.size() == 0) {
      continue;
    }
    std::string pack_name;
    std::string pack_path;

    // Find all the packs from loaded configuration
    for (auto const &conf_element : pack_element.second) {
      pack_name = std::string(conf_element.first.data());
      pack_path = std::string(conf_element.second.data());

      // Read each pack configuration in JSON
      pt::ptree pack_tree;
      Status status = osquery::parseJSON(pack_path, pack_tree);

      // Get all the parsed elements from the pack JSON file
      if (pack_tree.count(pack_name) == 0) {
        continue;
      }
      pt::ptree pack_file_element = pack_tree.get_child(pack_name);

      // Get all the valid packs and return them in a map
      std::map<std::string, pt::ptree> clean_packs = queryPackParser->QueryPackParsePacks(pack_file_element, false, false);

      // Iterate through the already parsed and valid packs
      std::map<std::string, pt::ptree>::iterator pk = clean_packs.begin();
      for(pk=clean_packs.begin(); pk!=clean_packs.end(); ++pk) {
        // Adding a prefix to the pack queries, to be easily found in the scheduled queries
        std::string pk_name = "pack_" + pack_name + "_" + pk->first;
        pt::ptree pk_data = pk->second;

        // Query data to return as Row
        r["query_name"] = TEXT(pk->first);
        r["name"] = TEXT(pack_name);
        r["path"] = TEXT(pack_path);
        r["query"] = TEXT(pk_data.get<std::string>("query"));
        r["interval"] = INTEGER(pk_data.get<int>("interval"));
        r["platform"] = TEXT(pk_data.get<std::string>("platform"));
        r["version"] = TEXT(pk_data.get<std::string>("version"));
        r["description"] = TEXT(pk_data.get<std::string>("description"));
        r["value"] = TEXT(pk_data.get<std::string>("value"));
        r["scheduled_name"] = TEXT(pk_name);
        int scheduled = Config::checkScheduledQuery(r["query"]) ? 1 : 0;
        r["scheduled"] = INTEGER(scheduled);

        results.push_back(r);
      }
    }
  }

  return results;
}
}
}
