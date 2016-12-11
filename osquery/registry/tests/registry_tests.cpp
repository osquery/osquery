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

#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

class RegistryTests : public testing::Test {};

class CatPlugin : public Plugin {
 public:
  CatPlugin() : some_value_(0) {}

  Status call(const PluginRequest&, PluginResponse&) override {
    return Status(0);
  }

 protected:
  int some_value_;
};

class HouseCat : public CatPlugin {
 public:
  Status setUp() {
    // Make sure the Plugin implementation's init is called.
    some_value_ = 9000;
    return Status(0, "OK");
  }
};

/// This is a manual registry type without a name, so we cannot broadcast
/// this registry type and it does NOT need to conform to a registry API.
class CatRegistry : public RegistryType<CatPlugin> {};

TEST_F(RegistryTests, test_registry) {
  CatRegistry cats("cats");

  /// Add a CatRegistry item (a plugin) called "house".
  cats.add<HouseCat>("house");
  EXPECT_EQ(cats.count(), 1U);

  /// Try to add the same plugin with the same name, this is meaningless.
  cats.add<HouseCat>("house");
  /// Now add the same plugin with a different name, a new plugin instance
  /// will be created and registered.
  cats.add<HouseCat>("house2");
  EXPECT_EQ(cats.count(), 2U);

  /// Request a plugin to call an API method.
  auto cat = cats.get("house");
  cats.setUp();

  /// Now let's iterate over every registered Cat plugin.
  EXPECT_EQ(cats.all().size(), 2U);
}

/// Normally we have "Registry" that dictates the set of possible API methods
/// for all registry types. Here we use a "TestRegistry" instead.
class TestCoreRegistry : public RegistryFactory {};

/// We can automatically create a registry type as long as that type conforms
/// to the registry API defined in the "Registry". Here we use "TestRegistry".
/// The above "CatRegistry" was easier to understand, but using a auto
/// registry via the registry create method, we can assign a tracked name
/// and then broadcast that registry name to other plugins.
auto AutoCatRegistry = TestCoreRegistry::create<CatPlugin>("cat");

TEST_F(RegistryTests, test_auto_factory) {
  /// Using the registry, and a registry type by name, we can register a
  /// plugin HouseCat called "house" like above.
  TestCoreRegistry::registry("cat")->add<HouseCat>("auto_house");
  TestCoreRegistry::add<HouseCat>("cat", "auto_house2");
  TestCoreRegistry::registry("cat")->setUp();

  /// When acting on registries by name we can check the broadcasted
  /// registry name of other plugin processes (via Thrift) as well as
  /// internally registered plugins like HouseCat.
  EXPECT_EQ(TestCoreRegistry::registry("cat")->count(), 2U);
  EXPECT_EQ(TestCoreRegistry::count("cat"), 2U);

  /// And we can call an API method, since we guarantee CatPlugins conform
  /// to the "TestCoreRegistry"'s "TestPluginAPI".
  auto cat = TestCoreRegistry::get("cat", "auto_house");
  auto same_cat = TestCoreRegistry::get("cat", "auto_house");
  EXPECT_EQ(cat, same_cat);
}

class DogPlugin : public Plugin {
 public:
  DogPlugin() : some_value_(10000) {}

 protected:
  int some_value_;
};

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

auto AutoDogRegistry = TestCoreRegistry::create<DogPlugin>("dog", true);

TEST_F(RegistryTests, test_auto_registries) {
  TestCoreRegistry::add<Doge>("dog", "doge");
  TestCoreRegistry::registry("dog")->setUp();

  EXPECT_EQ(TestCoreRegistry::count("dog"), 1U);
}

TEST_F(RegistryTests, test_persistant_registries) {
  EXPECT_EQ(TestCoreRegistry::count("cat"), 2U);
}

TEST_F(RegistryTests, test_registry_exceptions) {
  EXPECT_TRUE(TestCoreRegistry::add<Doge>("dog", "duplicate_dog").ok());
  // Bad dog will be added fine, but when setup is run, it will be removed.
  EXPECT_TRUE(TestCoreRegistry::add<BadDoge>("dog", "bad_doge").ok());
  TestCoreRegistry::registry("dog")->setUp();
  // Make sure bad dog does not exist.
  EXPECT_FALSE(TestCoreRegistry::exists("dog", "bad_doge"));
  EXPECT_EQ(TestCoreRegistry::count("dog"), 2U);

  unsigned int exception_count = 0;
  try {
    TestCoreRegistry::registry("does_not_exist");
  } catch (const std::out_of_range& /* e */) {
    exception_count++;
  }

  try {
    TestCoreRegistry::add<HouseCat>("does_not_exist", "cat");
  } catch (const std::out_of_range& /* e */) {
    exception_count++;
  }

  EXPECT_EQ(exception_count, 2U);
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
  return Status(0, "OK");
}

#define UNUSED(x) (void)(x)

TEST_F(RegistryTests, test_registry_api) {
  auto AutoWidgetRegistry = TestCoreRegistry::create<WidgetPlugin>("widgets");
  UNUSED(AutoWidgetRegistry);

  TestCoreRegistry::add<SpecialWidget>("widgets", "special");

  // Test route info propogation, from item to registry, to broadcast.
  auto ri = TestCoreRegistry::get("widgets", "special")->routeInfo();
  EXPECT_EQ(ri[0].at("name"), "special");
  auto rr = TestCoreRegistry::registry("widgets")->getRoutes();
  EXPECT_EQ(rr.size(), 1U);
  EXPECT_EQ(rr.at("special")[0].at("name"), "special");

  // Broadcast will include all registries, and all their items.
  auto broadcast_info = TestCoreRegistry::getBroadcast();
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
  EXPECT_TRUE(Registry::count() > 0U);

  bool has_one_registered = false;
  for (const auto& registry : Registry::all()) {
    if (Registry::count(registry.first) > 0) {
      has_one_registered = true;
      break;
    }
  }
  EXPECT_TRUE(has_one_registered);
}

TEST_F(RegistryTests, test_registry_modules) {
  // Test the registry's module loading state tracking.
  RegistryFactory::locked(false);
  EXPECT_FALSE(RegistryFactory::locked());
  RegistryFactory::locked(true);
  EXPECT_TRUE(RegistryFactory::locked());
  RegistryFactory::locked(false);

  // Test initializing a module load and the module's registry modifications.
  EXPECT_EQ(0U, RegistryFactory::getModule());
  RegistryFactory::initModule("/my/test/module");
  // The registry is locked, no modifications during module global ctors.
  EXPECT_TRUE(RegistryFactory::locked());
  // The 'is the registry using a module' is not set during module ctors.
  EXPECT_FALSE(RegistryFactory::usingModule());
  EXPECT_EQ(RegistryFactory::getModules().size(), 1U);
  // The unittest can introspect into the current module.
  auto& module = RegistryFactory::getModules().at(RegistryFactory::getModule());
  EXPECT_EQ(module.path, "/my/test/module");
  EXPECT_EQ(module.name, "");
  RegistryFactory::declareModule("test", "0.1.1", "0.0.0", "0.0.1");
  // The registry is unlocked after the module is declared.
  // This assures that module modifications happen with the correct information
  // and state tracking (aka the SDK limits, name, and version).
  EXPECT_FALSE(RegistryFactory::locked());
  // Now the 'is the registry using a module' is set for the duration of the
  // modules loading.
  EXPECT_TRUE(RegistryFactory::usingModule());
  EXPECT_EQ(module.name, "test");
  EXPECT_EQ(module.version, "0.1.1");
  EXPECT_EQ(module.sdk_version, "0.0.1");

  // Finally, when the module load is complete, we clear state.
  RegistryFactory::shutdownModule();
  // The registry is again locked.
  EXPECT_TRUE(RegistryFactory::locked());
  // And the registry is no longer using a module.
  EXPECT_FALSE(RegistryFactory::usingModule());
  EXPECT_EQ(0U, RegistryFactory::getModule());
}
}
