/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/database.h>

#include "osquery/config/parsers/query_packs.h"
#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

std::map<std::string, pt::ptree> QueryPackParsePacks(const pt::ptree& raw_packs,
                                                     bool check_platform,
                                                     bool check_version);

std::map<std::string, pt::ptree> getQueryPacksContent() {
  std::map<std::string, pt::ptree> result;
  pt::ptree pack_tree;
  std::string pack_path = kTestDataPath + "test_pack.conf";
  Status status = osquery::parseJSON(pack_path, pack_tree);
  pt::ptree pack_file_element = pack_tree.get_child("test_pack_test");

  ConfigDataInstance config;
  const auto& pack_parser = config.getParser("packs");
  if (pack_parser == nullptr) {
    return result;
  }
  const auto& queryPackParser =
      std::static_pointer_cast<QueryPackConfigParserPlugin>(pack_parser);
  if (queryPackParser == nullptr) {
    return result;
  }

  result = queryPackParser->QueryPackParsePacks(pack_file_element, false, true);

  return result;
}

std::map<std::string, pt::ptree> getQueryPacksExpectedResults() {
  std::map<std::string, pt::ptree> result;
  pt::ptree aux_data;

  std::string query = "select * from launchd";
  aux_data.put("query", query);
  int interval = 414141;
  aux_data.put("interval", interval);
  std::string platform = "whatever";
  aux_data.put("platform", platform);
  std::string version = "1.0.0";
  aux_data.put("version", version);
  std::string description = "Very descriptive description";
  aux_data.put("description", description);
  std::string value = "Value overflow";
  aux_data.put("value", value);

  result.insert(std::pair<std::string, pt::ptree>("launchd", aux_data));

  return result;
}

class QueryPacksConfigTests : public testing::Test {};

TEST_F(QueryPacksConfigTests, test_query_packs_configuration) {
  std::map<std::string, pt::ptree> data = getQueryPacksContent();
  std::map<std::string, pt::ptree> expected = getQueryPacksExpectedResults();
  EXPECT_EQ(expected["launchd"].get<std::string>("query"),
            data["launchd"].get<std::string>("query"));
  EXPECT_EQ(expected["launchd"].get<int>("interval"),
            data["launchd"].get<int>("interval"));
  EXPECT_EQ(expected["launchd"].get<std::string>("platform"),
            data["launchd"].get<std::string>("platform"));
  EXPECT_EQ(expected["launchd"].get<std::string>("version"),
            data["launchd"].get<std::string>("version"));
  EXPECT_EQ(expected["launchd"].get<std::string>("description"),
            data["launchd"].get<std::string>("description"));
  EXPECT_EQ(expected["launchd"].get<std::string>("value"),
            data["launchd"].get<std::string>("value"));
}
