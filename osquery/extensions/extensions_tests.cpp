/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdexcept>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>

#include <gtest/gtest.h>

#include <osquery/extensions.h>
#include <osquery/filesystem.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace osquery::extensions;

namespace osquery {

const int kDelayUS = 200;
const int kTimeoutUS = 10000;
const std::string kTestManagerSocket = "/tmp/osquery-em.socket";

class ExtensionsTest : public testing::Test {
 protected:
  void SetUp() {
    remove(kTestManagerSocket);
    if (pathExists(kTestManagerSocket).ok()) {
      throw std::domain_error("Cannot test sockets: " + kTestManagerSocket);
    }
  }

  void TearDown() {
    Dispatcher::getInstance().removeServices();
    remove(kTestManagerSocket);
  }

  bool ping(int attempts = 3) {
    // Open a socket to the test extension manager.
    boost::shared_ptr<TSocket> socket(new TSocket(kTestManagerSocket));
    boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

    ExtensionManagerClient client(protocol);

    // Calling open will except if the socket does not exist.
    ExtensionStatus status;
    for (int i = 0; i < attempts; ++i) {
      try {
        transport->open();
        client.ping(status);
        transport->close();
        return (status.code == ExtensionCode::EXT_SUCCESS);
      }
      catch (const std::exception& e) {
        ::usleep(kDelayUS);
      }
    }

    return false;
  }

  ExtensionList registeredExtensions(int attempts = 3) {
    // Open a socket to the test extension manager.
    boost::shared_ptr<TSocket> socket(new TSocket(kTestManagerSocket));
    boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

    ExtensionManagerClient client(protocol);

    // Calling open will except if the socket does not exist.
    ExtensionList extensions;
    for (int i = 0; i < attempts; ++i) {
      try {
        transport->open();
        client.extensions(extensions);
        transport->close();
      }
      catch (const std::exception& e) {
        ::usleep(kDelayUS);
      }
    }

    return extensions;
  }

  bool socketExists(const std::string& socket_path) {
    // Wait until the runnable/thread created the socket.
    int delay = 0;
    while (delay < kTimeoutUS) {
      if (pathExists(socket_path).ok() && isReadable(socket_path).ok()) {
        return true;
      }
      ::usleep(kDelayUS);
      delay += kDelayUS;
    }
    return false;
  }
};

TEST_F(ExtensionsTest, test_manager_runnable) {
  // Start a testing extension manager.
  auto status = startExtensionManager(kTestManagerSocket);
  EXPECT_TRUE(status.ok());
  // Call success if the Unix socket was created.
  EXPECT_TRUE(socketExists(kTestManagerSocket));
}

TEST_F(ExtensionsTest, test_extension_runnable) {
  auto status = startExtensionManager(kTestManagerSocket);
  EXPECT_TRUE(status.ok());
  // Wait for the extension manager to start.
  EXPECT_TRUE(socketExists(kTestManagerSocket));

  // Test the extension manager API 'ping' call.
  EXPECT_TRUE(ping());
}

TEST_F(ExtensionsTest, test_extension_start_failed) {
  auto status = startExtensionManager(kTestManagerSocket);
  EXPECT_TRUE(status.ok());
  // Wait for the extension manager to start.
  EXPECT_TRUE(socketExists(kTestManagerSocket));

  // Start an extension that does NOT fatal if the extension manager dies.
  status = startExtension(kTestManagerSocket, "test", "0.1", "0.0.1");
  // This will be false since we are registering duplicate items
  EXPECT_FALSE(status.ok());
}

TEST_F(ExtensionsTest, test_extension_start) {
  auto status = startExtensionManager(kTestManagerSocket);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(socketExists(kTestManagerSocket));

  // Now allow duplicates (for testing, since EM/E are the same).
  Registry::allowDuplicates(true);
  status = startExtension(kTestManagerSocket, "test", "0.1", "0.0.1");
  // This will be false since we are registering duplicate items
  EXPECT_TRUE(status.ok());

  // The `startExtension` internal call (exposed for testing) returns the
  // uuid of the extension in the success status.
  RouteUUID uuid;
  try {
    uuid = (RouteUUID)stoi(status.getMessage(), nullptr, 0);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
    return;
  }

  // We can test-wait for the extensions's socket to open.
  EXPECT_TRUE(socketExists(kTestManagerSocket + "." + std::to_string(uuid)));

  // Then clean up the registry modifications.
  Registry::removeBroadcast(uuid);
  Registry::allowDuplicates(false);
}

class ExtensionPlugin : public Plugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) {
    for (const auto& request_item : request) {
      response.push_back({{request_item.first, request_item.second}});
    }
    return Status(0, "Test sucess");
  }
};

class TestExtensionPlugin : public ExtensionPlugin {};

CREATE_REGISTRY(ExtensionPlugin, "extension_test");

TEST_F(ExtensionsTest, test_extension_broadcast) {
  auto status = startExtensionManager(kTestManagerSocket);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(socketExists(kTestManagerSocket));

  // This time we're going to add a plugin to the extension_test registry.
  REGISTER(TestExtensionPlugin, "extension_test", "test_item");

  // Now we create a registry alias that will be broadcasted but NOT used for
  // internal call lookups. Aliasing was introduced for testing such that an
  // EM/E could exist in the same process (the same registry) without having
  // duplicate registry items in the internal registry list AND extension
  // registry route table.
  Registry::addAlias("extension_test", "test_item", "test_alias");
  Registry::allowDuplicates(true);

  // Before registering the extension there is NO route to "test_alias" since
  // alias resolutions are performed by the EM.
  EXPECT_TRUE(Registry::exists("extension_test", "test_item"));
  EXPECT_FALSE(Registry::exists("extension_test", "test_alias"));

  status = startExtension(kTestManagerSocket, "test", "0.1", "0.0.1");
  EXPECT_TRUE(status.ok());

  RouteUUID uuid;
  try {
    uuid = (RouteUUID)stoi(status.getMessage(), nullptr, 0);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
    return;
  }

  auto ext_socket = kTestManagerSocket + "." + std::to_string(uuid);
  EXPECT_TRUE(socketExists(ext_socket));

  // Make sure the EM registered the extension (called in start extension).
  auto extensions = registeredExtensions();
  EXPECT_EQ(extensions.size(), 1);
  EXPECT_EQ(extensions.count(uuid), 1);
  EXPECT_EQ(extensions.at(uuid).name, "test");
  EXPECT_EQ(extensions.at(uuid).version, "0.1");
  EXPECT_EQ(extensions.at(uuid).sdk_version, "0.0.1");

  // We are broadcasting to our own registry in the test, which internally has
  // a "test_item" aliased to "test_alias", "test_item" is internally callable
  // but "test_alias" can only be resolved by an EM call.
  EXPECT_TRUE(Registry::exists("extension_test", "test_item"));
  // Now "test_alias" exists since it is in the extensions route table.
  EXPECT_TRUE(Registry::exists("extension_test", "test_alias"));

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
  EXPECT_EQ(response.size(), 1);
  EXPECT_EQ(response[0]["test_key"], "test_value");

  Registry::removeBroadcast(uuid);
  Registry::allowDuplicates(false);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
