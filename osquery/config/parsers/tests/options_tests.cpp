/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class OptionsConfigParserPluginTests : public testing::Test {};

TEST_F(OptionsConfigParserPluginTests, test_get_option) {
  Config c;
  auto s = c.update(getTestConfigMap());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(c.getParser("options")->getData().get_child("options").get<bool>(
                "enable_monitor"),
            true);
  c.reset();
}

TEST_F(OptionsConfigParserPluginTests, test_unknown_option) {
  Config c;
  std::map<std::string, std::string> update;

  update["awesome"] =
      "{\"options\": {\"fake\": 1, \"custom_fake\": 1, \"fake_custom_fake\": "
      "1}}";
  auto s = c.update(update);

  // This looks funky, because the parser is named 'options' and it claims
  // ownership of a single top-level-key called 'options'.
  auto options = c.getParser("options")->getData().get_child("options");

  // Since 'fake' was not defined as a flag, it is not an option.
  EXPECT_EQ(1U, options.count("fake"));
  EXPECT_TRUE(Flag::getValue("fake").empty());

  // The word 'custom_' must be a prefix.
  EXPECT_EQ(1U, options.count("fake_custom_fake"));
  EXPECT_TRUE(Flag::getValue("fake_custom_fake").empty());

  // This should work.
  EXPECT_EQ(1U, options.count("custom_fake"));
  EXPECT_EQ(1U, options.get<size_t>("custom_fake", 0U));
  EXPECT_FALSE(Flag::getValue("custom_fake").empty());
}
}
