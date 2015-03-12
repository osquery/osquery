/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>
#include <iostream>
#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using osquery::Status;

namespace osquery {

FLAG(string, config_path, "/var/osquery/osquery.conf", "Path to config file");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  virtual Status genConfig(std::map<std::string, std::string>& config);
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

Status FilesystemConfigPlugin::genConfig(
    std::map<std::string, std::string>& config) {
  std::vector<std::string> conf_files, file_contents;
  if (!fs::exists(FLAGS_config_path)) {
    return Status(1, "config file does not exist");
  }

  Status stat = resolveFilePattern(FLAGS_config_path + ".d/%.conf", conf_files);
  if (!stat.ok()) {
    VLOG(1) << "Error is resolving extra configuration files: "
            << stat.getMessage();
  }
  VLOG(1) << "Finished resolving, reading " << conf_files.size()
          << " additional JSONs";

  std::sort(conf_files.begin(), conf_files.end());
  conf_files.push_back(FLAGS_config_path);

  std::string content;

  for (const auto& path : conf_files) {
    readFile(path, content);
    config[path] = content;
  }

  return Status(0, "OK");
}
}
