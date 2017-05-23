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
  const std::string kConfigViews = "config_views";
};

Status ViewsConfigParserPlugin::setUp() {
  data_.put_child("views", pt::ptree());
  return Status(0, "OK");
}

Status ViewsConfigParserPlugin::update(const std::string& source,
                                       const ParserConfig& config) {
  // Drop previous config views (if any)
  std::string old_views;
  getDatabaseValue(kQueries, kConfigViews, old_views);
  for (const auto& v : osquery::split(old_views, ",")) {
    QueryData r;
    auto s = osquery::query("DROP VIEW " + v, r);
  }

  if (config.count("views") > 0) {
    data_ = pt::ptree();
    data_.put_child("views", config.at("views"));
  }
  const auto& views = data_.get_child("views");
  std::vector<std::string> created_views;
  for (const auto& view : views) {
    std::string query = views.get<std::string>(view.first, "");
    if (query.empty()) {
      continue;
    }
    QueryData results;
    auto s =
        osquery::query("CREATE VIEW " + view.first + " AS " + query, results);
    if (s.ok()) {
      LOG(INFO) << "Created view: " << view.first;
      created_views.push_back(view.first);
    } else {
      LOG(INFO) << "Error creating view (" << view.first
                << "): " << s.getMessage();
    }
  }
  setDatabaseValue(kQueries, kConfigViews, osquery::join(created_views, ","));
  return Status(0, "OK");
}

REGISTER_INTERNAL(ViewsConfigParserPlugin, "config_parser", "views");
}
