/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>

namespace osquery {

DECLARE_bool(disable_database);

class OptionsConfigParserPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();

    // Force registry to use ephemeral database plugin
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
  }
};

TEST_F(OptionsConfigParserPluginTests, test_get_option) {
  Config c;
  auto s = c.update(getTestConfigMap("test_parse_items.conf"));
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  const auto& parser = c.getParser("options")->getData();
  ASSERT_FALSE(parser.doc().HasMember("options"));

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
  const auto& doc = c.getParser("options")->getData().doc()["options"];

  // Since 'fake' was not defined as a flag, it is not an option.
  EXPECT_TRUE(doc.HasMember("fake"));
  EXPECT_TRUE(Flag::getValue("fake").empty());

  // The word 'custom_' must be a prefix.
  EXPECT_TRUE(doc.HasMember("fake_custom_fake"));
  EXPECT_TRUE(Flag::getValue("fake_custom_fake").empty());

  // This should work.
  ASSERT_TRUE(doc.HasMember("custom_fake"));
  EXPECT_TRUE(doc["custom_fake"].IsNumber());
  EXPECT_EQ(1U, doc["custom_fake"].GetUint());
  EXPECT_FALSE(Flag::getValue("custom_fake").empty());
}

TEST_F(OptionsConfigParserPluginTests, test_json_option) {
  Config c;
  std::map<std::string, std::string> update;

  update["awesome"] = R"raw({
    "options": {
      "custom_nested_json":
        {"foo":1,"bar":"baz"}
    }
  })raw";
  auto s = c.update(update);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  const auto& doc = c.getParser("options")->getData().doc()["options"];

  EXPECT_TRUE(doc.HasMember("custom_nested_json"));
  EXPECT_FALSE(Flag::getValue("custom_nested_json").empty());
  EXPECT_EQ(R"raw({"foo":1,"bar":"baz"})raw",
            Flag::getValue("custom_nested_json"));
}
}
