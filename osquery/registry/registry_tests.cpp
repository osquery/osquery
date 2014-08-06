// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/registry.h"

#include <memory>
#include <string>

#include <glog/logging.h>
#include <gtest/gtest.h>

class TestPlugin {
public:
  virtual std::string getName() {
    return "test_base";
  }
  virtual ~TestPlugin() {}
protected:
  TestPlugin() {};
};

DECLARE_REGISTRY(
  TestPlugins,
  std::string,
  std::shared_ptr<TestPlugin>)

#define REGISTERED_TEST_PLUGINS REGISTRY(TestPlugins)

#define REGISTER_TEST_PLUGIN(name, decorator) \
  REGISTER(TestPlugins, name, decorator)

class TestPluginInstance : public TestPlugin {
public:
  TestPluginInstance() {};

  std::string getName() {
    return std::string("test_1");
  }

  virtual ~TestPluginInstance() {}
};

REGISTER_TEST_PLUGIN("test_1", std::make_shared<TestPluginInstance>());

class RegistryTests : public testing::Test {
public:
  RegistryTests() {
    osquery::InitRegistry::get().run();
  }
};

TEST_F(RegistryTests, test_plugin_method) {
  auto plugin = REGISTERED_TEST_PLUGINS.at("test_1");
  EXPECT_EQ(plugin->getName(), "test_1");
}

TEST_F(RegistryTests, test_plugin_map) {
  EXPECT_EQ(REGISTERED_TEST_PLUGINS.size(), 1);
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
