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

#include <osquery/config.h>
#include <osquery/registry.h>

#include "osquery/core/test_util.h"

namespace osquery {

class FilePathsConfigParserPluginTests : public testing::Test {};

TEST_F(FilePathsConfigParserPluginTests, test_get_files) {
  // Read config content manually.
  std::string content;
  auto s = readFile(kTestDataPath + "test_parse_items.conf", content);
  EXPECT_TRUE(s.ok());

  // Construct a config map, the typical output from `Config::genConfig`.
  std::map<std::string, std::string> config;
  config["awesome"] = content;

  Config c;
  s = c.update(config);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  c.files(
      ([](const std::string& category, const std::vector<std::string>& files) {
        std::vector<std::string> value = {"/usr"};
        EXPECT_EQ(value, files);
      }));
}
}
