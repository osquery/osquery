/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

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

// Regression coverage for the extension-deregistration deadlock: see
// removeExternal (registry_interface.cpp) and removeBroadcast
// (registry_factory.cpp).

namespace {

RegistryInterface* kReentryRegistry{nullptr};
std::mutex kRemoveMutex;
std::condition_variable kRemoveCV;
bool kInRemoveCallback{false};

// Bound as a registry's remove_ callback; mirrors a table plugin whose DROP
// re-enters the registry for a shared lock (xCreate ->
// RegistryInterface::call).
class ReentrantPlugin : public Plugin {
 public:
  Status call(const PluginRequest&, PluginResponse&) override {
    return Status::success();
  }

  static void removeExternal(const std::string& /*name*/) {
    {
      std::lock_guard<std::mutex> lock(kRemoveMutex);
      kInRemoveCallback = true;
    }
    kRemoveCV.notify_all();

    // Let the writer thread queue its pending exclusive before we re-enter for
    // a shared lock; that ordering is what wedges the unpatched tree.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    if (kReentryRegistry != nullptr) {
      kReentryRegistry->names(); // takes a shared lock on mutex_
    }
  }
};

std::atomic<int> kDedupRemoveCount{0};
std::mutex kDedupBarrierMutex;
std::condition_variable kDedupBarrierCV;
int kDedupEntered{0};

class DedupPlugin : public Plugin {
 public:
  Status call(const PluginRequest&, PluginResponse&) override {
    return Status::success();
  }

  static void removeExternal(const std::string& /*name*/) {
    kDedupRemoveCount.fetch_add(1);
    // Force the two racing removers to overlap so the unpatched bug can't hide
    // behind serialization. The removers are released together, so both reach
    // here near-simultaneously; the short timeout only bounds the patched path,
    // where a single remover arrives and no second entrant is coming.
    std::unique_lock<std::mutex> lock(kDedupBarrierMutex);
    ++kDedupEntered;
    kDedupBarrierCV.notify_all();
    kDedupBarrierCV.wait_for(lock, std::chrono::milliseconds(500), [] {
      return kDedupEntered >= 2;
    });
  }
};

// Re-expose the protected external-route API so a test can drive removeExternal
// and a concurrent addExternal directly on one registry instance.
template <class PluginType>
class OpenRegistry : public RegistryType<PluginType> {
 public:
  explicit OpenRegistry(const std::string& name)
      : RegistryType<PluginType>(name) {}
  using RegistryInterface::addExternal;
  using RegistryInterface::removeExternal;
};

} // namespace

// removeExternal must not hold the registry lock while running the remove
// callback: a concurrent writer (addExternal) is pending during the callback,
// which re-enters for a shared lock. On buggy code this deadlocks BOTH the
// remover and the writer, so the writer runs on its own thread and this test
// thread only waits with a deadline -- otherwise it would hang, not fail.
TEST_F(RegistryTests, test_remove_external_no_deadlock) {
  auto registry = std::make_shared<OpenRegistry<ReentrantPlugin>>("reentrant");
  kReentryRegistry = registry.get();
  kInRemoveCallback = false;

  RegistryRoutes routes;
  routes["item"] = PluginResponse{};
  ASSERT_TRUE(registry->addExternal(1001, routes).ok());

  // Promises capture their state by shared_ptr so a thread wedged on a
  // regressed tree never touches freed test locals. Threads stay joinable: the
  // patched path joins them below instead of leaking detached workers.
  auto removed = std::make_shared<std::promise<void>>();
  auto removed_future = removed->get_future();
  std::thread remover([registry, removed]() {
    registry->removeExternal(1001);
    removed->set_value();
  });

  {
    std::unique_lock<std::mutex> lock(kRemoveMutex);
    EXPECT_TRUE(kRemoveCV.wait_for(
        lock, std::chrono::seconds(5), [] { return kInRemoveCallback; }));
  }

  // addExternal takes a WriteLock, making a writer pending while the callback
  // runs. On its own thread because it blocks too on the unpatched tree.
  auto added = std::make_shared<std::promise<void>>();
  auto added_future = added->get_future();
  std::thread writer([registry, added]() {
    RegistryRoutes routes2;
    routes2["item2"] = PluginResponse{};
    registry->addExternal(2002, routes2);
    added->set_value();
  });

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  bool ok = removed_future.wait_until(deadline) == std::future_status::ready &&
            added_future.wait_until(deadline) == std::future_status::ready;

  if (ok) {
    // Both finished: join them, then clear the global with no reader running.
    remover.join();
    writer.join();
    kReentryRegistry = nullptr;
  } else {
    // Regressed tree: the workers are wedged and cannot be joined without
    // hanging the suite. Detach so this test reports the failure and exits;
    // leave kReentryRegistry set -- nulling it would race the wedged reader.
    remover.detach();
    writer.detach();
  }
  ASSERT_TRUE(ok)
      << "removeExternal deadlocked: registry lock held across remove callback";
}

// Two concurrent removers of the same uuid (Thrift deregister vs. watcher reap)
// must run the removal exactly once: removeBroadcast claims the uuid by erasing
// it under the write lock.
TEST_F(RegistryTests, test_remove_broadcast_dedup) {
  // Register the dedup registry exactly once for the process: add() throws on a
  // duplicate registry name, so an unguarded add breaks a repeated run.
  static const bool kDedupRegistered = [] {
    TestCoreRegistry::get().add(
        "dedup", std::make_shared<RegistryType<DedupPlugin>>("dedup"));
    return true;
  }();
  (void)kDedupRegistered;

  RegistryRoutes routes;
  routes["dedup_item"] = PluginResponse{};
  RegistryBroadcast broadcast;
  broadcast["dedup"] = routes;
  ASSERT_TRUE(TestCoreRegistry::get().addBroadcast(4004, broadcast).ok());

  kDedupRemoveCount = 0;
  kDedupEntered = 0;

  std::promise<void> gate;
  auto gate_future = gate.get_future().share();
  std::vector<Status> results(2);
  std::vector<std::thread> threads;
  for (int i = 0; i < 2; ++i) {
    threads.emplace_back([i, gate_future, &results]() {
      gate_future.wait();
      results[i] = TestCoreRegistry::get().removeBroadcast(4004);
    });
  }
  gate.set_value();
  for (auto& t : threads) {
    t.join();
  }

  int ok_count = (results[0].ok() ? 1 : 0) + (results[1].ok() ? 1 : 0);
  EXPECT_EQ(ok_count, 1);
  EXPECT_EQ(kDedupRemoveCount.load(), 1);
}

} // namespace osquery
