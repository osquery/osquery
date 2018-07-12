/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class FilePathsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    // Read config content manually.
    readFile(kTestDataPath + "test_parse_items.conf", content_);

    // Construct a config map, the typical output from `Config::genConfig`.
    config_data_["awesome"] = content_;
    Config::get().reset();
  }

  void TearDown() override {
    Config::get().reset();
  }

  size_t numFiles() {
    size_t count = 0;
    Config::get().files(([&count](
        const std::string&, const std::vector<std::string>&) { count++; }));
    return count;
  }

 protected:
  std::string content_;
  std::map<std::string, std::string> config_data_;
};

TEST_F(FilePathsConfigParserPluginTests, test_get_files) {
  std::vector<std::string> expected_categories = {
      "config_files", "config_files_query", "logs", "logs"};
  std::vector<std::string> categories;
  std::vector<std::string> expected_values = {
      "/dev", "/dev/zero", "/dev/urandom", "/dev/null", "/dev/random"};
  std::vector<std::string> values;

  Config::get().update(config_data_);
  Config::get().files(([&categories, &values](
      const std::string& category, const std::vector<std::string>& files) {
    categories.push_back(category);
    for (const auto& file : files) {
      values.push_back(file);
    }
  }));

  EXPECT_EQ(categories, expected_categories);
  EXPECT_EQ(values, expected_values);
}

TEST_F(FilePathsConfigParserPluginTests, test_get_file_accesses) {
  Config::get().update(config_data_);
  auto parser = Config::getParser("file_paths");
  const auto& doc = parser->getData();

  size_t accesses = 0_sz;
  if (doc.doc().HasMember("file_accesses") &&
      doc.doc()["file_accesses"].IsArray()) {
    accesses = doc.doc()["file_accesses"].Size();
  }
  EXPECT_EQ(accesses, 2_sz);
}

TEST_F(FilePathsConfigParserPluginTests, test_remove_source) {
  Config::get().update(config_data_);
  Config::get().removeFiles("awesome");
  // Expect the pack's set to persist.
  // Do not call removeFiles, instead only update the pack/config content.
  EXPECT_EQ(numFiles(), 1U);

  // This will clear all source data for 'awesome'.
  config_data_["awesome"] = "";
  Config::get().update(config_data_);
  EXPECT_EQ(numFiles(), 0U);
}
}
