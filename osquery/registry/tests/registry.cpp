/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>

namespace osquery {

/// Normally we have "Registry" that dictates the set of possible API methods
/// for all registry types. Here we use a "TestRegistry" instead.
class TestCoreRegistry : public RegistryFactory {};

class CatPlugin : public Plugin {
 public:
  CatPlugin() : some_value_(0) {}

  Status call(const PluginRequest&, PluginResponse&) override {
    return Status(0);
  }

 protected:
  int some_value_;
};

class DogPlugin : public Plugin {
 public:
  DogPlugin() : some_value_(10000) {}

  Status call(const PluginRequest&, PluginResponse&) override {
    return Status(0);
  }

 protected:
  int some_value_;
};

class RegistryTests : public testing::Test {
 public:
  void SetUp() override {
    if (!kSetUp) {
      TestCoreRegistry::get().add(
          "cat", std::make_shared<RegistryType<CatPlugin>>("cat"));
      TestCoreRegistry::get().add(
          "dog", std::make_shared<RegistryType<DogPlugin>>("dog"));
      kSetUp = true;
    }
  }

  static bool kSetUp;
};

bool RegistryTests::kSetUp{false};

class HouseCat : public CatPlugin {
 public:
  Status setUp() {
    // Make sure the Plugin implementation's init is called.
    some_value_ = 9000;
    return Status::success();
  }
};

/// This is a manual registry type without a name, so we cannot broadcast
/// this registry type and it does NOT need to conform to a registry API.
class CatRegistry : public RegistryType<CatPlugin> {
 public:
  CatRegistry(const std::string& name) : RegistryType(name) {}
};

TEST_F(RegistryTests, test_registry) {
  CatRegistry cats("cats");

  /// Add a CatRegistry item (a plugin) called "house".
  cats.add("house", std::make_shared<HouseCat>());
  EXPECT_EQ(cats.count(), 1U);

  /// Try to add the same plugin with the same name, this is meaningless.
  cats.add("house", std::make_shared<HouseCat>());

  /// Now add the same plugin with a different name, a new plugin instance
  /// will be created and registered.
  cats.add("house2", std::make_shared<HouseCat>());
  EXPECT_EQ(cats.count(), 2U);

  /// Request a plugin to call an API method.
  auto cat = cats.plugin("house");
  cats.setUp();

  /// Now let's iterate over every registered Cat plugin.
  EXPECT_EQ(cats.plugins().size(), 2U);
}

TEST_F(RegistryTests, test_auto_factory) {
  /// Using the registry, and a registry type by name, we can register a
  /// plugin HouseCat called "house" like above.
  auto cat_registry = TestCoreRegistry::get().registry("cat");
  cat_registry->add("auto_house", std::make_shared<HouseCat>());
  cat_registry->setUp();

  /// When acting on registries by name we can check the broadcasted
  /// registry name of other plugin processes (via Thrift) as well as
  /// internally registered plugins like HouseCat.
  EXPECT_EQ(TestCoreRegistry::get().registry("cat")->count(), 1U);
  EXPECT_EQ(TestCoreRegistry::get().count("cat"), 1U);

  /// And we can call an API method, since we guarantee CatPlugins conform
  /// to the "TestCoreRegistry"'s "TestPluginAPI".
  auto cat = TestCoreRegistry::get().plugin("cat", "auto_house");
  auto same_cat = TestCoreRegistry::get().plugin("cat", "auto_house");
  EXPECT_EQ(cat, same_cat);
}

class Doge : public DogPlugin {
 public:
  Doge() {
    some_value_ = 100000;
  }
};

class BadDoge : public DogPlugin {
 public:
  Status setUp() {
    return Status(1, "Expect error... this is a bad dog");
  }
};

TEST_F(RegistryTests, test_auto_registries) {
  auto dog_registry = TestCoreRegistry::get().registry("dog");
  dog_registry->add("doge", std::make_shared<Doge>());
  dog_registry->setUp();

  EXPECT_EQ(TestCoreRegistry::get().count("dog"), 1U);
}

TEST_F(RegistryTests, test_persistent_registries) {
  EXPECT_EQ(TestCoreRegistry::get().count("cat"), 1U);
}

TEST_F(RegistryTests, test_registry_exceptions) {
  auto dog_registry = TestCoreRegistry::get().registry("dog");
  EXPECT_TRUE(dog_registry->add("doge2", std::make_shared<Doge>()).ok());
  // Bad dog will be added fine.
  EXPECT_TRUE(dog_registry->add("bad_doge", std::make_shared<BadDoge>()).ok());
  dog_registry->setUp();
  // Make sure bad dog does exist.
  EXPECT_TRUE(TestCoreRegistry::get().exists("dog", "bad_doge"));
  EXPECT_EQ(TestCoreRegistry::get().count("dog"), 3U);

  unsigned int exception_count = 0;
  try {
    TestCoreRegistry::get().registry("does_not_exist");
  } catch (const std::runtime_error& /* e */) {
    exception_count++;
  }

  EXPECT_EQ(exception_count, 1U);
}

class WidgetPlugin : public Plugin {
 public:
  /// The route information will usually be provided by the plugin type.
  /// The plugin/registry item will set some structures for the plugin
  /// to parse and format. BUT a plugin/registry item can also fill this
  /// information in if the plugin type/registry type exposes routeInfo as
  /// a virtual method.
  PluginResponse routeInfo() const {
    PluginResponse info;
    info.push_back({{"name", name_}});
    return info;
  }

  /// Plugin types should contain generic request/response formatters and
  /// decorators.
  std::string secretPower(const PluginRequest& request) const {
    if (request.count("secret_power") > 0U) {
      return request.at("secret_power");
    }
    return "no_secret_power";
  }
};

class SpecialWidget : public WidgetPlugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response);
};

Status SpecialWidget::call(const PluginRequest& request,
                           PluginResponse& response) {
  response.push_back(request);
  response[0]["from"] = name_;
  response[0]["secret_power"] = secretPower(request);
  return Status::success();
}

#define UNUSED(x) (void)(x)

TEST_F(RegistryTests, test_registry_api) {
  TestCoreRegistry::get().add(
      "widgets", std::make_shared<RegistryType<WidgetPlugin>>("widgets"));

  auto widgets = TestCoreRegistry::get().registry("widgets");
  widgets->add("special", std::make_shared<SpecialWidget>());

  // Test route info propagation, from item to registry, to broadcast.
  auto ri = TestCoreRegistry::get().plugin("widgets", "special")->routeInfo();
  EXPECT_EQ(ri[0].at("name"), "special");

  auto rr = TestCoreRegistry::get().registry("widgets")->getRoutes();
  EXPECT_EQ(rr.size(), 1U);
  EXPECT_EQ(rr.at("special")[0].at("name"), "special");

  // Broadcast will include all registries, and all their items.
  auto broadcast_info = TestCoreRegistry::get().getBroadcast();
  EXPECT_TRUE(broadcast_info.size() >= 3U);
  EXPECT_EQ(broadcast_info.at("widgets").at("special")[0].at("name"),
            "special");

  PluginResponse response;
  PluginRequest request;
  auto status = TestCoreRegistry::call("widgets", "special", request, response);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response[0].at("from"), "special");
  EXPECT_EQ(response[0].at("secret_power"), "no_secret_power");

  request["secret_power"] = "magic";
  status = TestCoreRegistry::call("widgets", "special", request, response);
  EXPECT_EQ(response[0].at("secret_power"), "magic");
}

TEST_F(RegistryTests, test_real_registry) {
  EXPECT_TRUE(Registry::get().count() > 0U);

  bool has_one_registered = false;
  for (const auto& registry : Registry::get().all()) {
    if (Registry::get().count(registry.first) > 0) {
      has_one_registered = true;
      break;
    }
  }
  EXPECT_TRUE(has_one_registered);
}
}
