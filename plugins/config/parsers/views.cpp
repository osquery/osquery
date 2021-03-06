/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>

#include <osquery/config/config.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for a "views" dictionary key.
 */
class ViewsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"views"};
  }

  Status update(const std::string& source, const ParserConfig& config) override;

 private:
  const std::string kConfigViews = "config_views.";
  std::atomic<bool> first_time_{true};
};

Status ViewsConfigParserPlugin::update(const std::string& source,
                                       const ParserConfig& config) {
  auto cv = config.find("views");
  if (cv == config.end()) {
    return Status(1);
  }

  {
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(cv->second.doc(), obj);
    doc.add("views", obj);
    data_ = std::move(doc);
  }

  const auto& views = data_.doc()["views"];

  // We use a restricted scope below to change the data structure from
  // an array to a set. This lets us do deletes much more efficiently
  std::vector<std::string> created_views;
  std::set<std::string> erase_views;
  {
    std::vector<std::string> old_views_vec;
    scanDatabaseKeys(kQueries, old_views_vec, kConfigViews);
    for (const auto& view : old_views_vec) {
      erase_views.insert(view.substr(kConfigViews.size()));
    }
  }

  QueryData r;
  if (views.IsObject()) {
    for (const auto& view : views.GetObject()) {
      std::string name = view.name.GetString();
      if (!view.value.IsString()) {
        continue;
      }
      std::string query = view.value.GetString();
      if (query.empty()) {
        continue;
      }

      std::string old_query;
      getDatabaseValue(kQueries, kConfigViews + name, old_query);
      erase_views.erase(name);

      // If query exists in the store, view would already have been
      // created and we don't need to create it. Except, at startup,
      // the view always needs to be created.
      if (!first_time_ && old_query == query) {
        continue;
      }

#ifdef OSQUERY_IS_FUZZING
      auto s = Status::success();
#else
      // View has been updated
      osquery::query("DROP VIEW " + name, r);
      auto s = osquery::query("CREATE VIEW " + name + " AS " + query, r);
#endif
      if (s.ok()) {
        setDatabaseValue(kQueries, kConfigViews + name, query);
      } else {
        LOG(INFO) << "Error creating view (" << name << "): " << s.getMessage();
      }
    }
  }

  // Any views left are views that don't exist in the new configuration file
  // so we tear them down and remove them from the database.
  for (const auto& old_view : erase_views) {
#ifndef OSQUERY_IS_FUZZING
    osquery::query("DROP VIEW " + old_view, r);
#endif
    deleteDatabaseValue(kQueries, kConfigViews + old_view);
  }

  first_time_ = false;
  return Status(0, "OK");
}

REGISTER_INTERNAL(ViewsConfigParserPlugin, "config_parser", "views");
} // namespace osquery
