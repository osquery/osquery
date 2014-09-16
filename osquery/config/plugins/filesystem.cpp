// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/config/plugin.h"

#include <fstream>

#include <boost/filesystem/operations.hpp>

namespace fs = boost::filesystem;
using osquery::Status;

namespace osquery {

DEFINE_string(config_path, "/var/osquery/osquery.conf", "Path to config file");

class FilesystemConfigPlugin : public ConfigPlugin {
 public:
  FilesystemConfigPlugin() {};

  std::pair<osquery::Status, std::string> genConfig() {
    std::string config;
    if (!fs::exists(FLAGS_config_path)) {
      return std::make_pair(Status(1, "config file does not exist"), config);
    }

    std::ifstream config_stream(FLAGS_config_path);

    config_stream.seekg(0, std::ios::end);
    config.reserve(config_stream.tellg());
    config_stream.seekg(0, std::ios::beg);

    config.assign((std::istreambuf_iterator<char>(config_stream)),
                  std::istreambuf_iterator<char>());
    return std::make_pair(Status(0, "OK"), config);
  }

  virtual ~FilesystemConfigPlugin() {}
};

REGISTER_CONFIG_PLUGIN(
    "filesystem", std::make_shared<osquery::FilesystemConfigPlugin>());
}
