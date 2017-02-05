/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/json.h"

namespace errc = boost::system::errc;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

CLI_FLAG(string,
         config_path,
         (fs::path(OSQUERY_HOME) / "osquery.conf").make_preferred().string(),
         "Path to JSON config file");

CLI_FLAG(uint64,
         config_filesystem_refresh,
         0,
         "Optional interval in seconds to re-read configuration");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config);
  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack);

 private:
  bool started_thread_{false};
  void start();
};

class FilesystemConfigRefreshRunner : public InternalRunnable {
 public:
  /// A simple wait/interruptible lock.
  void start();
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

Status FilesystemConfigPlugin::genConfig(
    std::map<std::string, std::string>& config) {
  boost::system::error_code ec;
  if (!fs::is_regular_file(FLAGS_config_path, ec) ||
      ec.value() != errc::success) {
    return Status(1, "config file does not exist: " + FLAGS_config_path);
  }

  std::vector<std::string> conf_files;
  resolveFilePattern(FLAGS_config_path + ".d/%.conf", conf_files);
  std::sort(conf_files.begin(), conf_files.end());
  conf_files.push_back(FLAGS_config_path);

  for (const auto& path : conf_files) {
    std::string content;
    if (readFile(path, content).ok()) {
      config[path] = content;
    }
  }

  // If the initial configuration includes a non-0 refresh, start an additional
  // service that sleeps and periodically regenerates the configuration.
  if (!started_thread_ && FLAGS_config_filesystem_refresh >= 1) {
    Dispatcher::addService(std::make_shared<FilesystemConfigRefreshRunner>());
    started_thread_ = true;
  }

  return Status(0, "OK");
}

Status FilesystemConfigPlugin::genPack(const std::string& name,
                                       const std::string& value,
                                       std::string& pack) {
  if (name == "*") {
    // The config requested a multi-pack.
    std::vector<std::string> paths;
    resolveFilePattern(value, paths);

    pt::ptree multi_pack;
    for (const auto& path : paths) {
      std::string content;
      if (!readFile(path, content)) {
        LOG(WARNING) << "Cannot read multi-pack file: " << path;
        continue;
      }

      // Assemble an intermediate property tree for simplified parsing.
      pt::ptree single_pack;
      stripConfigComments(content);
      try {
        std::stringstream json_stream;
        json_stream << content;
        pt::read_json(json_stream, single_pack);
      } catch (const pt::json_parser::json_parser_error& /* e */) {
        LOG(WARNING) << "Cannot read multi-pack JSON: " << path;
        continue;
      }

      multi_pack.put_child(fs::path(path).stem().string(), single_pack);
    }

    // We should have a property tree of pack content mimicking embedded
    // configuration packs, ready to parse as a string.
    std::ostringstream output;
    pt::write_json(output, multi_pack, false);
    pack = output.str();
    if (pack.empty()) {
      return Status(1, "Multi-pack content empty");
    }

    return Status(0);
  }

  boost::system::error_code ec;
  if (!fs::is_regular_file(value, ec) || ec.value() != errc::success) {
    return Status(1, value + " is not a valid path");
  }

  return readFile(value, pack);
}

void FilesystemConfigRefreshRunner::start() {
  while (!interrupted()) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    pauseMilli(FLAGS_config_filesystem_refresh * 1000);
    // Since the pause occurs before the logic, we need to check for an
    // interruption request.
    if (interrupted()) {
      return;
    }

    // Access the configuration.
    auto plugin = RegistryFactory::get().plugin("config", "filesystem");
    if (plugin != nullptr) {
      auto config_plugin = std::dynamic_pointer_cast<ConfigPlugin>(plugin);

      std::map<std::string, std::string> config;
      if (config_plugin->genConfig(config)) {
        LOG(INFO) << "Reloading configuration from disk";
        Config::getInstance().update(config);
      }
    }
  }
}
}
