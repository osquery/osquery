/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
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
    return {"file_paths", "file_accesses", "exclude_paths"};
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
  data_.put_child("exclude_paths", pt::ptree());
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

  Config::get().removeFiles(source);

  std::set<std::string> valid_categories;
  for (const auto& category : data_.get_child("file_paths")) {
    for (const auto& path : category.second) {
      auto pattern = path.second.get_value<std::string>("");
      if (pattern.empty()) {
        continue;
      }
      replaceGlobWildcards(pattern);
      Config::get().addFile(source, category.first, pattern);
      valid_categories.insert(category.first);
    }
  }

  if (config.count("exclude_paths") > 0) {
    data_.put_child("exclude_paths", config.at("exclude_paths"));
  }

  std::set<std::string> invalid_categories;
  for (const auto& excl_category : data_.get_child("exclude_paths")) {
    if (valid_categories.find(excl_category.first) == valid_categories.end()) {
      // valid_categories contains all the valid categories collected from
      // traversing "file_paths" above.
      invalid_categories.insert(excl_category.first);
    }
  }

  for (const auto& invalid_category : invalid_categories) {
    // invalid_categories contains all the categories which are mentioned in
    // exclude_paths but not found in file_paths.
    data_.get_child("exclude_paths").erase(invalid_category);
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(FilePathsConfigParserPlugin, "config_parser", "file_paths");
}
