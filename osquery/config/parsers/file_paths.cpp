/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for an "file_paths" dictionary key.
 */
class FilePathsConfigParserPlugin : public ConfigParserPlugin {
 public:
  FilePathsConfigParserPlugin();
  virtual ~FilePathsConfigParserPlugin() {}

  std::vector<std::string> keys() const override {
    return {"file_paths", "file_accesses"};
  }

  Status setUp() override { return Status(0); };

  Status update(const std::string& source, const ParserConfig& config) override;

 private:
  /// The access map binds source to category.
  std::map<std::string, std::vector<std::string> > access_map_;
};

FilePathsConfigParserPlugin::FilePathsConfigParserPlugin() {
  data_.put_child("file_paths", pt::ptree());
  data_.put_child("file_accesses", pt::ptree());
}

Status FilePathsConfigParserPlugin::update(const std::string& source,
                                           const ParserConfig& config) {
  if (config.count("file_paths") > 0) {
    data_.put_child("file_paths", config.at("file_paths"));
  }

  auto& accesses = data_.get_child("file_accesses");
  if (config.count("file_accesses") > 0) {
    if (access_map_.count(source) > 0) {
      access_map_.erase(source);
    }

    for (const auto& category : config.at("file_accesses")) {
      auto path = category.second.get_value<std::string>("");
      access_map_[source].push_back(path);
    }
    // Regenerate the access:
    for (const auto& access_source : access_map_) {
      for (const auto& category : access_source.second) {
        accesses.put(category, access_source.first);
      }
    }
  }

  Config::getInstance().removeFiles(source);
  for (const auto& category : data_.get_child("file_paths")) {
    for (const auto& path : category.second) {
      auto pattern = path.second.get_value<std::string>("");
      if (pattern.empty()) {
        VLOG(1) << "Empty pattern from path " << path.first
                << " in config source: " << source;
        continue;
      }
      replaceGlobWildcards(pattern);
      Config::getInstance().addFile(source, category.first, pattern);
    }
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(FilePathsConfigParserPlugin, "config_parser", "file_paths");
}
