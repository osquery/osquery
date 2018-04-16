/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifdef GTEST_HAS_TR1_TUPLE
#undef GTEST_HAS_TR1_TUPLE
#define GTEST_HAS_TR1_TUPLE 0
#endif

#include <stdexcept>

#include <gtest/gtest.h>

#include <osquery/extensions.h>
#include <osquery/filesystem.h>

#include "osquery/core/process.h"
#include "osquery/extensions/interface.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tests/test_util.h"

using namespace osquery::extensions;

namespace osquery {

const int kDelay{20};
const int kTimeout{3000};

class ExtensionsTest : public testing::Test {
 protected:
  void SetUp() override {
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      socket_path = OSQUERY_SOCKET;
    } else {
      socket_path = kTestWorkingDirectory;
    }

    socket_path += "testextmgr" + std::to_string(rand());

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      removePath(socket_path);
      if (pathExists(socket_path).ok()) {
        throw std::domain_error("Cannot test sockets: " + socket_path);
      }
    }
  }

  void TearDown() override {
    Dispatcher::stopServices();
    Dispatcher::joinServices();

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      removePath(socket_path);
    }
  }

  bool ping(int attempts = 3) {
    // Calling open will except if the socket does not exist.
    ExtensionStatus status;
    for (int i = 0; i < attempts; ++i) {
      try {
        EXManagerClient client(socket_path);
        client.get()->API_PING(status);
        return (status.code == (int)ExtensionCode::EXT_SUCCESS);
      } catch (const std::exception& /* e */) {
        sleepFor(kDelay);
      }
    }

    return false;
  }

  QueryData query(const std::string& sql, int attempts = 3) {
    // Calling open will except if the socket does not exist.
    ExtensionResponse response;
    for (int i = 0; i < attempts; ++i) {
      try {
        EXManagerClient client(socket_path);
        client.get()->API_QUERY(response, sql);
      } catch (const std::exception& /* e */) {
        sleepFor(kDelay);
      }
    }

    QueryData qd;
    for (const auto& row : response.response) {
      qd.push_back(row);
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
    int delay{0};
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
  EXPECT_TRUE(status.ok());
  // Call success if the Unix socket was created.
  EXPECT_TRUE(socketExistsLocal(socket_path));
}

TEST_F(ExtensionsTest, test_extension_runnable) {
  auto status = startExtensionManager(socket_path);
  EXPECT_TRUE(status.ok());
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
  // This will not be false since we are allowing deplicate items.
  // Otherwise, starting an extension and extensionManager would fatal.
  ASSERT_TRUE(status.ok());

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
    return Status(0, "Test success");
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

TEST_F(ExtensionsTest, test_extension_module_search) {
  createMockFileStructure();
  tearDownMockFileStructure();
}
}
