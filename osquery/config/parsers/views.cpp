/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <set>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/conversions.h"

namespace rj = rapidjson;

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
};

Status ViewsConfigParserPlugin::update(const std::string& source,
                                       const ParserConfig& config) {
  auto cv = config.find("views");
  if (cv == config.end()) {
    return Status(1);
  }

  auto obj = data_.getObject();
  data_.copyFrom(cv->second.doc(), obj);
  data_.add("views", obj);

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

      std::string old_query = "";
      getDatabaseValue(kQueries, kConfigViews + name, old_query);
      erase_views.erase(name);
      if (old_query == query) {
        continue;
      }

      // View has been updated
      osquery::query("DROP VIEW " + name, r);
      auto s = osquery::query("CREATE VIEW " + name + " AS " + query, r);
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
    osquery::query("DROP VIEW " + old_view, r);
    deleteDatabaseValue(kQueries, kConfigViews + old_view);
  }
  return Status(0, "OK");
}

REGISTER_INTERNAL(ViewsConfigParserPlugin, "config_parser", "views");
}
