/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/config/default_paths.h>

#include <osquery/utils/json/json.h>

namespace errc = boost::system::errc;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

CLI_FLAG(string,
         config_path,
         (fs::path(OSQUERY_HOME) / "osquery.conf").make_preferred().string(),
         "Path to JSON config file");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config);
  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack);
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

Status FilesystemConfigPlugin::genConfig(
    std::map<std::string, std::string>& config) {
  boost::system::error_code ec;
  if (!fs::is_regular_file(FLAGS_config_path, ec) ||
      ec.value() != errc::success) {
    return Status::failure("config file does not exist: " + FLAGS_config_path);
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
} // namespace osquery
