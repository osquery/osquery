/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef GTEST_HAS_TR1_TUPLE
#undef GTEST_HAS_TR1_TUPLE
#define GTEST_HAS_TR1_TUPLE 0
#endif

#include <stdexcept>

#include <gtest/gtest.h>

#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry_factory.h>

#include <osquery/utils/info/platform_type.h>

#include <osquery/database/database.h>
#include <osquery/extensions/interface.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/process/process.h>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(extensions_require);

const int kDelay = 20;
const int kTimeout = 3000;

class ExtensionsTest : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      socket_path =
          (fs::temp_directory_path() /
           fs::unique_path("osquery.extensions_test.testextmgr.%%%%.%%%%"))
              .string();
      removePath(socket_path);
      if (pathExists(socket_path).ok()) {
        throw std::domain_error("Cannot test sockets: " + socket_path);
      }
    } else {
      socket_path =
          "\\\\.\\pipe\\" +
          fs::unique_path("osquery.extensions_test.testextmgr.%%%%.%%%%")
              .string();
    }
  }

  void TearDown() override {
    resetDispatcher();

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      fs::remove(fs::path(socket_path));
    }
  }

  void resetDispatcher() {
    auto& dispatcher = Dispatcher::instance();
    dispatcher.stopServices();
    dispatcher.joinServices();
    dispatcher.resetStopping();
  }

  bool ping(int attempts = 3) {
    // Calling open will except if the socket does not exist.
    for (int i = 0; i < attempts; ++i) {
      try {
        ExtensionManagerClient client(socket_path);

        auto status = client.ping();
        return (status.getCode() == (int)ExtensionCode::EXT_SUCCESS);
      } catch (const std::exception& /* e */) {
        sleepFor(kDelay);
      }
    }

    return false;
  }

  QueryData query(const std::string& sql, int attempts = 3) {
    // Calling open will except if the socket does not exist.
    QueryData qd;
    for (int i = 0; i < attempts; ++i) {
      try {
        ExtensionManagerClient client(socket_path);

        client.query(sql, qd);
      } catch (const std::exception& /* e */) {
        sleepFor(kDelay);
      }
    }

    return qd;
  }

  ExtensionList registeredExtensions(int attempts = 3) {
    ExtensionList extensions;
    for (int i = 0; i < attempts; ++i) {
      if (getExtensions(socket_path, extensions).ok()) {
        break;
      }
    }

    return extensions;
  }

  bool socketExistsLocal(const std::string& check_path) {
    // Wait until the runnable/thread created the socket.
    int delay = 0;
    while (delay < kTimeout) {
      if (osquery::socketExists(check_path).ok()) {
        return true;
      }
      sleepFor(kDelay);
      delay += kDelay;
    }
    return false;
  }

 public:
  std::string socket_path;
};

TEST_F(ExtensionsTest, test_manager_runnable) {
  // Start a testing extension manager.
  auto status = startExtensionManager(socket_path);
  ASSERT_TRUE(status.ok()) << " error " << status.what();
  // Call success if the Unix socket was created.
  EXPECT_TRUE(socketExistsLocal(socket_path));
}

TEST_F(ExtensionsTest, test_manager_bad_socket) {
  auto status = startExtensionManager("/this/doesnt/exist");
  EXPECT_FALSE(status.ok());
}

TEST_F(ExtensionsTest, test_manager_bad_require_extension) {
  FLAGS_extensions_require = "this_extension_doesnt_exist";
  auto status = startExtensionManager(socket_path);
  ASSERT_FALSE(status.ok());
  EXPECT_TRUE(status.getMessage().find("Required extension not found") !=
              std::string::npos);
  FLAGS_extensions_require = "";
}

TEST_F(ExtensionsTest, test_extension_runnable) {
  auto status = startExtensionManager(socket_path);
  EXPECT_TRUE(status.ok()) << " error " << status.what();
  // Wait for the extension manager to start.
  EXPECT_TRUE(socketExistsLocal(socket_path));

  // Test the extension manager API 'ping' call.
  EXPECT_TRUE(ping());
}

TEST_F(ExtensionsTest, test_extension_start) {
  auto status = startExtensionManager(socket_path);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(socketExistsLocal(socket_path));

  auto& rf = RegistryFactory::get();
  // Now allow duplicates (for testing, since EM/E are the same).
  rf.allowDuplicates(true);
  status = startExtension(socket_path, "test", "0.1", "0.0.0", "9.9.9");
  // This will not be false since we are allowing duplicate items.
  // Otherwise, starting an extension and extensionManager would fatal.
  ASSERT_NE(status.getCode(), (int)ExtensionCode::EXT_FAILED) << status.what();

  // Checks for version comparisons (also used by packs).
  ASSERT_FALSE(versionAtLeast("1.1.1", "0.0.1"));
  ASSERT_TRUE(versionAtLeast("1.1.1", "1.1.1"));
  ASSERT_TRUE(versionAtLeast("1.1.1", "1.1.2"));

  // The `startExtension` internal call (exposed for testing) returns the
  // uuid of the extension in the success status.
  RouteUUID uuid = (RouteUUID)stoi(status.getMessage(), nullptr, 0);

  // We can test-wait for the extensions's socket to open.
  EXPECT_TRUE(socketExistsLocal(socket_path + "." + std::to_string(uuid)));

  // Then clean up the registry modifications.
  rf.removeBroadcast(uuid);
  rf.allowDuplicates(false);
}

class ExtensionPlugin : public Plugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) {
    for (const auto& request_item : request) {
      response.push_back({{request_item.first, request_item.second}});
    }
    return Status::success();
  }
};

class TestExtensionPlugin : public ExtensionPlugin {};

CREATE_REGISTRY(ExtensionPlugin, "extension_test");

TEST_F(ExtensionsTest, test_extension_broadcast) {
  auto status = startExtensionManager(socket_path);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(socketExistsLocal(socket_path));

  auto& rf = RegistryFactory::get();
  // This time we're going to add a plugin to the extension_test registry.
  rf.registry("extension_test")
      ->add("test_item", std::make_shared<TestExtensionPlugin>());

  // Now we create a registry alias that will be broadcasted but NOT used for
  // internal call lookups. Aliasing was introduced for testing such that an
  // EM/E could exist in the same process (the same registry) without having
  // duplicate registry items in the internal registry list AND extension
  // registry route table.
  rf.addAlias("extension_test", "test_item", "test_alias");
  rf.allowDuplicates(true);

  // Before registering the extension there is NO route to "test_alias" since
  // alias resolutions are performed by the EM.
  EXPECT_TRUE(rf.exists("extension_test", "test_item"));
  EXPECT_FALSE(rf.exists("extension_test", "test_alias"));

  status = startExtension(socket_path, "test", "0.1", "0.0.0", "0.0.0");
  EXPECT_TRUE(status.ok());

  RouteUUID uuid;
  try {
    uuid = (RouteUUID)stoi(status.getMessage(), nullptr, 0);
  } catch (const std::exception& /* e */) {
    EXPECT_TRUE(false);
    return;
  }

  auto ext_socket = socket_path + "." + std::to_string(uuid);
  EXPECT_TRUE(socketExistsLocal(ext_socket));

  // Make sure the EM registered the extension (called in start extension).
  auto extensions = registeredExtensions();
  // Expect two, since `getExtensions` includes the core.
  ASSERT_EQ(extensions.size(), 2U);
  EXPECT_EQ(extensions.count(uuid), 1U);
  EXPECT_EQ(extensions.at(uuid).name, "test");
  EXPECT_EQ(extensions.at(uuid).version, "0.1");
  EXPECT_EQ(extensions.at(uuid).sdk_version, "0.0.0");

  // We are broadcasting to our own registry in the test, which internally has
  // a "test_item" aliased to "test_alias", "test_item" is internally callable
  // but "test_alias" can only be resolved by an EM call.
  EXPECT_TRUE(rf.exists("extension_test", "test_item"));
  // Now "test_alias" exists since it is in the extensions route table.
  EXPECT_TRUE(rf.exists("extension_test", "test_alias"));

  PluginResponse response;
  // This registry call will fail, since "test_alias" cannot be resolved using
  // a local registry call.
  status = Registry::call("extension_test", "test_alias", {{}}, response);
  EXPECT_FALSE(status.ok());

  // The following will be the result of a:
  //   Registry::call("extension_test", "test_alias", {{}}, response);
  status = callExtension(ext_socket,
                         "extension_test",
                         "test_alias",
                         {{"test_key", "test_value"}},
                         response);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.size(), 1U);
  EXPECT_EQ(response[0]["test_key"], "test_value");

  rf.removeBroadcast(uuid);
  rf.allowDuplicates(false);
}

} // namespace osquery
