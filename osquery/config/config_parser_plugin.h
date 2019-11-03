/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/core/plugins/plugin.h>
#include <osquery/utils/json/json.h>

#include <map>
#include <string>
#include <vector>

namespace osquery {

/**
 * @brief A pluggable configuration parser.
 *
 * An osquery config instance is populated from JSON using a ConfigPlugin.
 * That plugin may update the config data asynchronously and read from
 * several sources, as is the case with "filesystem" and reading multiple files.
 *
 * A ConfigParserPlugin will receive the merged configuration at osquery start
 * and the updated (still merged) config if any ConfigPlugin updates the
 * instance asynchronously. Each parser specifies a set of top-level JSON
 * keys to receive. The config instance will auto-merge the key values
 * from multiple sources.
 *
 * The keys must contain either dictionaries or lists.
 *
 * If a top-level key is a dictionary, each source with the top-level key
 * will have its own dictionary keys merged and replaced based on the lexical
 * order of sources. For the "filesystem" config plugin this is the lexical
 * sorting of filenames. If the top-level key is a list, each source with the
 * top-level key will have its contents appended.
 *
 * Each config parser plugin will live alongside the config instance for the
 * life of the osquery process. The parser may perform actions at config load
 * and config update "time" as well as keep its own data members and be
 * accessible through the Config class API.
 */
class ConfigParserPlugin : public Plugin {
 public:
  using ParserConfig = std::map<std::string, JSON>;

 public:
  /**
   * @brief Return a list of top-level config keys to receive in updates.
   *
   * The ConfigParserPlugin::update method will receive a map of these keys
   * with a JSON-parsed document of configuration data.
   *
   * @return A list of string top-level JSON keys.
   */
  virtual std::vector<std::string> keys() const = 0;

  /**
   * @brief Receive a merged JSON document for each top-level config key.
   *
   * Called when the Config instance is initially loaded with data from the
   * active config plugin and when it is updated via an async ConfigPlugin
   * update. Every config parser will receive a map of merged data for each key
   * they requested in keys().
   *
   * @param source source of the config data
   * @param config A JSON-parsed document map.
   * @return Failure if the parser should no longer receive updates.
   */
  virtual Status update(const std::string& source,
                        const ParserConfig& config) = 0;

  /// Allow parsers to perform some setup before the configuration is loaded.
  Status setUp() override;

  Status call(const PluginRequest& /*request*/,
              PluginResponse& /*response*/) override {
    return Status(0);
  }

  /**
   * @brief Accessor for parser-manipulated data.
   *
   * Parsers should be used generically, for places within the code base that
   * request a parser (check for its existence), should only use this
   * ConfigParserPlugin::getData accessor.
   *
   * More complex parsers that require dynamic casting are not recommended.
   */
  const JSON& getData() const {
    return data_;
  }

 protected:
  /// Allow the config to request parser state resets.
  virtual void reset();

 protected:
  /// Allow the config parser to keep some global state.
  JSON data_;

 private:
  friend class Config;
};
} // namespace osquery
