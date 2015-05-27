/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>

#include <boost/filesystem/operations.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {

CLI_FLAG(string,
         config_path,
         "/var/osquery/osquery.conf",
         "Path to JSON config file");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config);
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

Status FilesystemConfigPlugin::genConfig(
    std::map<std::string, std::string>& config) {
  if (!fs::is_regular_file(FLAGS_config_path)) {
    return Status(1, "config file does not exist");
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
}
