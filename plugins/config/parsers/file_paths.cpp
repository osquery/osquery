/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

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
  // Parse and update file_accesses top-level key.
  void updateFileAccesses(const JSON& file_accesses, const std::string& source);

  // Parse and update file_paths top-level key.
  void updateFilePaths(const JSON& file_paths, const std::string& source);

  // Parse and update file_paths_query top-level key.
  void updateFilePathsQuery(const JSON& file_paths_query,
                            const std::string& source);

  // Parse and update exclude_paths top-level key.
  void updateExcludePaths(const JSON& exclude_paths);

 private:
  /// The access map binds source to category.
  std::map<std::string, std::vector<std::string>> access_map_;
};

Status FilePathsConfigParserPlugin::setUp() {
  auto accesses_arr = data_.getArray();
  data_.add("file_accesses", accesses_arr);
  auto exclude_obj = data_.getObject();
  data_.add("exclude_paths", exclude_obj);

  access_map_.clear();
  return Status::success();
}

void FilePathsConfigParserPlugin::updateFileAccesses(
    const JSON& file_accesses, const std::string& source) {
  if (!file_accesses.doc().IsArray()) {
    return;
  }

  for (const auto& category : file_accesses.doc().GetArray()) {
    if (!category.IsString()) {
      continue;
    }
    std::string path = category.GetString();
    access_map_[source].push_back(path);
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

void FilePathsConfigParserPlugin::updateFilePaths(const JSON& file_paths,
                                                  const std::string& source) {
  if (!file_paths.doc().IsObject()) {
    return;
  }

  for (const auto& category : file_paths.doc().GetObject()) {
    if (!category.value.IsArray() || !category.name.IsString()) {
      continue;
    }

    std::string name = category.name.GetString();
    for (const auto& path : category.value.GetArray()) {
      if (!path.IsString()) {
        continue;
      }

      std::string pattern = path.GetString();
      if (pattern.empty()) {
        continue;
      }

      replaceGlobWildcards(pattern);
      Config::get().addFile(source, name, pattern);
    }
  }
}

void FilePathsConfigParserPlugin::updateFilePathsQuery(
    const JSON& file_paths_query, const std::string& source) {
#ifdef OSQUERY_IS_FUZZING
  return;
#else

  if (!file_paths_query.doc().IsObject()) {
    return;
  }

  for (const auto& category : file_paths_query.doc().GetObject()) {
    if (!category.value.IsArray() || !category.name.IsString()) {
      continue;
    }

    std::string name = category.name.GetString();
    for (const auto& query : category.value.GetArray()) {
      if (!query.IsString()) {
        continue;
      }

      auto sql = SQL(query.GetString());
      if (!sql.ok()) {
        LOG(ERROR) << "Could not add file_paths using file_paths_query '"
                   << query.GetString() << "': " << sql.getMessageString();
      } else {
        for (const auto& row : sql.rows()) {
          auto pathIt = row.find("path");
          if (pathIt == row.end()) {
            LOG(ERROR) << "Cold not find non-empty 'path' column in the "
                          "results of file_paths_query '"
                       << query.GetString() << "'";
          } else {
            std::string path = pathIt->second;
            replaceGlobWildcards(path);
            Config::get().addFile(source, name, path);
          }
        }
      }
    }
  }
#endif
}

void FilePathsConfigParserPlugin::updateExcludePaths(
    const JSON& exclude_paths) {
  if (!exclude_paths.doc().IsObject()) {
    return;
  }

  auto obj = data_.getObject();
  for (const auto& category : exclude_paths.doc().GetObject()) {
    if (!category.value.IsArray() || !category.name.IsString()) {
      continue;
    }

    auto arr = data_.getArray();
    std::string category_string = category.name.GetString();
    for (const auto& path : category.value.GetArray()) {
      if (!path.IsString()) {
        continue;
      }

      std::string path_string = path.GetString();
      data_.pushCopy(path_string, arr);
    }
    data_.add(category_string, arr, obj);
  }

  // Will attempt a merge so be careful that the key is initialized.
  if (!data_.doc().HasMember("exclude_paths")) {
    auto exclude_obj = data_.getObject();
    data_.add("exclude_paths", exclude_obj);
  }
  data_.mergeObject(data_.doc()["exclude_paths"], obj);
}

Status FilePathsConfigParserPlugin::update(const std::string& source,
                                           const ParserConfig& config) {
  Config::get().removeFiles(source);
  access_map_.erase(source);

  auto file_paths = config.find("file_paths");
  auto file_paths_query = config.find("file_paths_query");
  if (file_paths == config.end() && file_paths_query == config.end()) {
    return Status::success();
  }

  if (file_paths != config.end()) {
    updateFilePaths(file_paths->second, source);
  }

  if (file_paths_query != config.end()) {
    updateFilePathsQuery(file_paths_query->second, source);
  }

  auto file_accesses = config.find("file_accesses");
  if (file_accesses != config.end()) {
    updateFileAccesses(file_accesses->second, source);
  }

  auto exclude_paths = config.find("exclude_paths");
  if (exclude_paths != config.end()) {
    updateExcludePaths(exclude_paths->second);
  }

  auto doc = JSON::newObject();
  doc.copyFrom(data_.doc());
  data_ = std::move(doc);

  return Status::success();
}

REGISTER_INTERNAL(FilePathsConfigParserPlugin, "config_parser", "file_paths");
} // namespace osquery
