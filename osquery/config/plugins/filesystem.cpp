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

#include <boost/filesystem/operations.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;
using osquery::Status;

namespace osquery {

DEFINE_osquery_flag(string,
                    config_path,
                    "/var/osquery/osquery.conf",
                    "Path to config file");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  virtual std::pair<osquery::Status, std::string> genConfig();
};

REGISTER(FilesystemConfigPlugin, "config", "filesystem");

std::pair<osquery::Status, std::string> FilesystemConfigPlugin::genConfig() {
  std::string config;
  if (!fs::exists(FLAGS_config_path)) {
    return std::make_pair(Status(1, "config file does not exist"), config);
  }

  VLOG(1) << "Filesystem ConfigPlugin reading: " << FLAGS_config_path;
  std::ifstream config_stream(FLAGS_config_path);

  config_stream.seekg(0, std::ios::end);
  config.reserve(config_stream.tellg());
  config_stream.seekg(0, std::ios::beg);

  config.assign((std::istreambuf_iterator<char>(config_stream)),
                std::istreambuf_iterator<char>());
  return std::make_pair(Status(0, "OK"), config);
}
}
