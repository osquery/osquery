/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <set>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for a "views" dictionary key.
 */
class ViewsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"views"};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;

 private:
  const std::string kConfigViews = "config_views.";
};

Status ViewsConfigParserPlugin::setUp() {
  data_.put_child("views", pt::ptree());
  return Status(0, "OK");
}

Status ViewsConfigParserPlugin::update(const std::string& source,
                                       const ParserConfig& config) {
  if (config.count("views") > 0) {
    data_ = pt::ptree();
    data_.put_child("views", config.at("views"));
  }
  const auto& views = data_.get_child("views");
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
  for (const auto& view : views) {
    std::string name = view.first;
    std::string query = views.get<std::string>(view.first, "");
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
  for (const auto& old_view : erase_views) {
    osquery::query("DROP VIEW " + old_view, r);
    deleteDatabaseValue(kQueries, kConfigViews + old_view);
  }
  return Status(0, "OK");
}

REGISTER_INTERNAL(ViewsConfigParserPlugin, "config_parser", "views");
}
