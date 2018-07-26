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
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for an "file_paths" dictionary key.
 */
class FilePathsConfigParserPlugin : public ConfigParserPlugin {
 public:
  virtual ~FilePathsConfigParserPlugin() = default;

  std::vector<std::string> keys() const override {
    return {"file_paths", "file_paths_query", "file_accesses", "exclude_paths"};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;

 private:
  /// The access map binds source to category.
  std::map<std::string, std::vector<std::string> > access_map_;
};

Status FilePathsConfigParserPlugin::setUp() {
  auto paths_obj = data_.getObject();
  data_.add("file_paths", paths_obj);
  auto paths_query_obj = data_.getObject();
  data_.add("file_paths_query", paths_query_obj);
  auto accesses_arr = data_.getArray();
  data_.add("file_accesses", accesses_arr);
  auto exclude_obj = data_.getObject();
  data_.add("exclude_paths", exclude_obj);
  return Status();
}

Status FilePathsConfigParserPlugin::update(const std::string& source,
                                           const ParserConfig& config) {
  Config::get().removeFiles(source);
  access_map_.erase(source);
  if (config.count("file_paths") == 0 &&
      config.count("file_paths_query") == 0) {
    return Status();
  }

  if (config.count("file_accesses") > 0) {
    const auto& accesses = config.at("file_accesses").doc();
    if (accesses.IsArray()) {
      for (const auto& category : accesses.GetArray()) {
        if (!category.IsString()) {
          continue;
        }
        std::string path = category.GetString();
        access_map_[source].push_back(path);
      }
    }

    auto arr = data_.getArray();
    std::set<std::string> valid_categories;
    for (const auto& access_source : access_map_) {
      for (const auto& category : access_source.second) {
        valid_categories.insert(category);
      }
    }

    for (const auto& category : valid_categories) {
      data_.pushCopy(category, arr);
    }
    data_.add("file_accesses", arr);
  }

  if (config.count("file_paths") > 0) {
    // We know this top-level is an Object.
    const auto& file_paths = config.at("file_paths").doc();
    if (file_paths.IsObject()) {
      for (const auto& category : file_paths.GetObject()) {
        if (category.value.IsArray()) {
          for (const auto& path : category.value.GetArray()) {
            std::string pattern = path.GetString();
            if (pattern.empty()) {
              continue;
            }

            std::string name = category.name.GetString();
            replaceGlobWildcards(pattern);
            Config::get().addFile(source, name, pattern);
          }
        }
      }
    }
  }

  if (config.count("file_paths_query") > 0) {
    // We know this top-level is an Object.
    const auto& path_query_node = config.at("file_paths_query").doc();
    if (path_query_node.IsObject()) {
      for (const auto& category : path_query_node.GetObject()) {
        if (category.value.IsArray()) {
          std::string name = category.name.GetString();
          for (const auto& query : category.value.GetArray()) {
            auto sql = SQL(query.GetString());
            if (!sql.ok()) {
              LOG(ERROR) << "Could not add file_paths using file_paths_query '"
                         << query.GetString()
                         << "': " << sql.getMessageString();
            } else {
              for (const auto& row : sql.rows()) {
                auto pathIt = row.find("path");
                if (pathIt == row.end()) {
                  LOG(ERROR) << "Cold not find non-empty 'path' column in the "
                                "results of file_paths_query '"
                             << query.GetString();
                } else {
                  std::string path = pathIt->second;
                  replaceGlobWildcards(path);
                  Config::get().addFile(source, name, path);
                }
              }
            }
          }
        }
      }
    }
  }

  // We know this top-level is an Object.
  if (config.count("exclude_paths") > 0) {
    auto obj = data_.getObject();
    const auto& exclude_paths = config.at("exclude_paths").doc();
    if (exclude_paths.IsObject()) {
      for (const auto& category : exclude_paths.GetObject()) {
        auto arr = data_.getArray();
        if (category.value.IsArray()) {
          std::string category_string = category.name.GetString();
          for (const auto& path : category.value.GetArray()) {
            std::string path_string = path.GetString();
            data_.pushCopy(path_string, arr);
          }
          data_.add(category_string, arr, obj);
        }
      }
    }

    if (!data_.doc().HasMember("exclude_paths")) {
      data_.add("exclude_paths", obj);
    } else {
      data_.mergeObject(data_.doc()["exclude_paths"], obj);
    }
  }

  return Status();
}

REGISTER_INTERNAL(FilePathsConfigParserPlugin, "config_parser", "file_paths");
}
