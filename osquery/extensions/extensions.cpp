/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <csignal>

#ifdef FBOSQUERY
#include <thrift/lib/cpp/concurrency/ThreadManager.h>
#include <thrift/lib/cpp/concurrency/PosixThreadFactory.h>
#include <thrift/lib/cpp/server/example/TThreadPoolServer.h>
#include <thrift/lib/cpp/protocol/TBinaryProtocol.h>
#include <thrift/lib/cpp/transport/TServerSocket.h>
#include <thrift/lib/cpp/transport/TBufferTransports.h>
#include <thrift/lib/cpp/transport/TSocket.h>
#define _SHARED_PTR std
#else
#include <thrift/concurrency/ThreadManager.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>
#define _SHARED_PTR boost
#endif

#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;
using namespace apache::thrift::concurrency;

using namespace osquery::extensions;

namespace osquery {

const int kWatcherMLatency = 3000;

FLAG(bool, disable_extensions, false, "Disable extension API");

FLAG(string,
     extensions_socket,
     "/var/osquery/osquery.em",
     "Path to the extensions UNIX domain socket")

/// Internal accessor for extension clients.
class EXInternal {
 public:
  EXInternal(const std::string& path)
      : socket_(new TSocket(path)),
        transport_(new TBufferedTransport(socket_)),
        protocol_(new TBinaryProtocol(transport_)) {}

  virtual ~EXInternal() { transport_->close(); }

 protected:
  _SHARED_PTR::shared_ptr<TSocket> socket_;
  _SHARED_PTR::shared_ptr<TTransport> transport_;
  _SHARED_PTR::shared_ptr<TProtocol> protocol_;
};

/// Internal accessor for a client to an extension (from an extension manager).
class EXClient : public EXInternal {
 public:
  EXClient(const std::string& path) : EXInternal(path) {
    client_ = std::make_shared<ExtensionClient>(protocol_);
    transport_->open();
  }

  const std::shared_ptr<ExtensionClient>& get() { return client_; }

 private:
  std::shared_ptr<ExtensionClient> client_;
};

/// Internal accessor for a client to an extension manager (from an extension).
class EXManagerClient : public EXInternal {
 public:
  EXManagerClient(const std::string& manager_path) : EXInternal(manager_path) {
    client_ = std::make_shared<ExtensionManagerClient>(protocol_);
    transport_->open();
  }

  const std::shared_ptr<ExtensionManagerClient>& get() { return client_; }

 private:
  std::shared_ptr<ExtensionManagerClient> client_;
};

namespace extensions {

void ExtensionHandler::ping(ExtensionStatus& _return) {
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "pong";
}

void ExtensionHandler::call(ExtensionResponse& _return,
                            const std::string& registry,
                            const std::string& item,
                            const ExtensionPluginRequest& request) {
  // Call will receive an extension or core's request to call the other's
  // internal registry call. It is the ONLY actor that resolves registry
  // item aliases.
  auto local_item = Registry::getAlias(registry, item);

  PluginResponse response;
  PluginRequest plugin_request;
  for (const auto& request_item : request) {
    plugin_request[request_item.first] = request_item.second;
  }

  auto status = Registry::call(registry, local_item, request, response);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& response_item : response) {
      _return.response.push_back(response_item);
    }
  }
}

void ExtensionManagerHandler::registerExtension(
    ExtensionStatus& _return,
    const InternalExtensionInfo& info,
    const ExtensionRegistry& registry) {
  if (exists(info.name)) {
    LOG(WARNING) << "Refusing to register duplicate extension " << info.name;
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Duplicate extension registered";
    return;
  }

  // Every call to registerExtension is assigned a new RouteUUID.
  RouteUUID uuid = rand();
  LOG(INFO) << "Registering extension (" << info.name << ", " << uuid
            << ", version=" << info.version << ", sdk=" << info.sdk_version
            << ")";

  if (!Registry::addBroadcast(uuid, registry).ok()) {
    LOG(WARNING) << "Could not add extension (" << info.name << ", " << uuid
                 << ") broadcast to registry";
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Failed adding registry broadcast";
    return;
  }

  extensions_[uuid] = info;
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "OK";
  _return.uuid = uuid;
}

void ExtensionManagerHandler::deregisterExtension(
    ExtensionStatus& _return, const ExtensionRouteUUID uuid) {
  if (extensions_.count(uuid) == 0) {
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "No extension UUID registered";
    return;
  }

  Registry::removeBroadcast(uuid);
  extensions_.erase(uuid);
}

void ExtensionManagerHandler::query(ExtensionResponse& _return,
                                    const std::string& sql) {
  QueryData results;
  auto status = osquery::query(sql, results);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& row : results) {
      _return.response.push_back(row);
    }
  }
}

void ExtensionManagerHandler::getQueryColumns(ExtensionResponse& _return,
                                              const std::string& sql) {
  tables::TableColumns columns;
  auto status = osquery::getQueryColumns(sql, columns);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& column : columns) {
      _return.response.push_back({{column.first, column.second}});
    }
  }
}

bool ExtensionManagerHandler::exists(const std::string& name) {
  std::vector<RouteUUID> removed_routes;
  const auto uuids = Registry::routeUUIDs();
  for (const auto& ext : extensions_) {
    // Find extension UUIDs that have gone away.
    if (std::find(uuids.begin(), uuids.end(), ext.first) == uuids.end()) {
      removed_routes.push_back(ext.first);
    }
  }

  // Remove each from the manager's list of extenion metadata.
  for (const auto& uuid : removed_routes) {
    extensions_.erase(uuid);
  }

  // Search the remaining extension list for duplicates.
  for (const auto& extension : extensions_) {
    if (extension.second.name == name) {
      return true;
    }
  }
  return false;
}
}

ExtensionRunner::~ExtensionRunner() { remove(path_); }

void ExtensionRunner::enter() {
  // Set the socket information for the extension manager.
  auto socket_path = path_;

  // Create the thrift instances.
  _SHARED_PTR::shared_ptr<ExtensionHandler> handler(new ExtensionHandler());
  _SHARED_PTR::shared_ptr<TProcessor> processor(new ExtensionProcessor(handler));
  _SHARED_PTR::shared_ptr<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  _SHARED_PTR::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  _SHARED_PTR::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  _SHARED_PTR::shared_ptr<ThreadManager> threadManager =
      ThreadManager::newSimpleThreadManager(FLAGS_worker_threads);
  _SHARED_PTR::shared_ptr<PosixThreadFactory> threadFactory =
      _SHARED_PTR::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
  threadManager->threadFactory(threadFactory);
  threadManager->start();

  // Start the Thrift server's run loop.
  try {
    TThreadPoolServer server(processor,
                             serverTransport,
                             transportFactory,
                             protocolFactory,
                             threadManager);
    server.serve();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Cannot start extension handler: " << socket_path << " ("
               << e.what() << ")";
    return;
  }
}

ExtensionManagerRunner::~ExtensionManagerRunner() {
  // Remove the socket path.
  remove(path_);
}

void ExtensionManagerRunner::enter() {
  // Set the socket information for the extension manager.
  auto socket_path = path_;

  // Create the thrift instances.
  _SHARED_PTR::shared_ptr<ExtensionManagerHandler> handler(
      new ExtensionManagerHandler());
  _SHARED_PTR::shared_ptr<TProcessor> processor(
      new ExtensionManagerProcessor(handler));
  _SHARED_PTR::shared_ptr<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  _SHARED_PTR::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  _SHARED_PTR::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  _SHARED_PTR::shared_ptr<ThreadManager> threadManager =
      ThreadManager::newSimpleThreadManager(FLAGS_worker_threads);
  _SHARED_PTR::shared_ptr<PosixThreadFactory> threadFactory =
      _SHARED_PTR::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
  threadManager->threadFactory(threadFactory);
  threadManager->start();

  // Start the Thrift server's run loop.
  try {
    TThreadPoolServer server(processor,
                             serverTransport,
                             transportFactory,
                             protocolFactory,
                             threadManager);
    server.serve();
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extensions disabled: cannot start extension manager ("
                 << socket_path << ") (" << e.what() << ")";
  }
}

void ExtensionWatcher::enter() {
  // Watch the manager, if the socket is removed then the extension will die.
  while (true) {
    watch();
    interruptableSleep(interval_);
  }
}

void ExtensionWatcher::exitFatal(int return_code) {
  // Exit the extension.
  ::exit(return_code);
}

void ExtensionWatcher::watch() {
  ExtensionStatus status;
  try {
    auto client = EXManagerClient(path_);
    // Ping the extension manager until it goes down.
    client.get()->ping(status);
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extension watcher ending: osquery core has gone away";
    exitFatal(0);
  }

  if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
    exitFatal();
  }
}

void ExtensionManagerWatcher::watch() {
  // Watch the set of extensions, if the socket is removed then the extension
  // will be deregistered.
  const auto uuids = Registry::routeUUIDs();

  ExtensionStatus status;
  for (const auto& uuid : uuids) {
    try {
      auto client = EXClient(getExtensionSocket(uuid));

      // Ping the extension until it goes down.
      client.get()->ping(status);
    } catch (const std::exception& e) {
      LOG(INFO) << "Extension UUID " << uuid << " has gone away";
      Registry::removeBroadcast(uuid);
    }

    if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
      Registry::removeBroadcast(uuid);
    }
  }
}

Status startExtension(const std::string& name, const std::string& version) {
  return startExtension(name, version, "0.0.0");
}

Status startExtension(const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version) {
  // No assumptions about how the extensions logs, the first action is to
  // start the extension's registry.
  Registry::setUp();

  auto status =
      startExtensionWatcher(FLAGS_extensions_socket, kWatcherMLatency, true);
  if (!status.ok()) {
    // If the threaded watcher fails to start, fail the extension.
    return status;
  }

  status = startExtension(
      FLAGS_extensions_socket, name, version, min_sdk_version, kSDKVersion);
  if (!status.ok()) {
    // If the extension failed to start then the EM is most likely unavailable.
    return status;
  }

  try {
    Dispatcher::joinServices();
  } catch (const std::exception& e) {
    // The extension manager may shutdown without notifying the extension.
    return Status(0, e.what());
  }

  // An extension will only return on failure.
  return Status(0, "OK");
}

Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version,
                      const std::string& sdk_version) {
  // Make sure the extension manager path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  // The Registry broadcast is used as the ExtensionRegistry.
  auto broadcast = Registry::getBroadcast();

  InternalExtensionInfo info;
  info.name = name;
  info.version = version;
  info.sdk_version = sdk_version;
  info.min_sdk_version = min_sdk_version;

  // Register the extension's registry broadcast with the manager.
  ExtensionStatus status;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->registerExtension(status, info, broadcast);
  }
  catch (const std::exception& e) {
    return Status(1, "Extension register failed: " + std::string(e.what()));
  }

  if (status.code != ExtensionCode::EXT_SUCCESS) {
    return Status(status.code, status.message);
  }

  // Now that the uuid is known, try to clean up stale socket paths.
  auto extension_path = getExtensionSocket(status.uuid, manager_path);
  if (pathExists(extension_path).ok()) {
    if (!isWritable(extension_path).ok()) {
      return Status(1, "Cannot write extension socket: " + extension_path);
    }

    if (!remove(extension_path).ok()) {
      return Status(1, "Cannot remove extension socket: " + extension_path);
    }
  }

  // Start the extension's Thrift server
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionRunner>(manager_path, status.uuid));
  VLOG(1) << "Extension (" << name << ", " << status.uuid << ", " << version
          << ", " << sdk_version << ") registered";
  return Status(0, std::to_string(status.uuid));
}

Status queryExternal(const std::string& manager_path,
                     const std::string& query,
                     QueryData& results) {
  // Make sure the extension path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  ExtensionResponse response;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->query(response, query);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  for (const auto& row : response.response) {
    results.push_back(row);
  }

  return Status(response.status.code, response.status.message);
}

Status queryExternal(const std::string& query, QueryData& results) {
  return queryExternal(FLAGS_extensions_socket, query, results);
}

Status getQueryColumnsExternal(const std::string& manager_path,
                               const std::string& query,
                               tables::TableColumns& columns) {
  // Make sure the extension path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  ExtensionResponse response;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->getQueryColumns(response, query);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Translate response map: {string: string} to a vector: pair(name, type).
  for (const auto& column : response.response) {
    for (const auto& column_detail : column) {
      columns.push_back(make_pair(column_detail.first, column_detail.second));
    }
  }

  return Status(response.status.code, response.status.message);
}

Status getQueryColumnsExternal(const std::string& query,
                               tables::TableColumns& columns) {
  return getQueryColumnsExternal(FLAGS_extensions_socket, query, columns);
}

Status pingExtension(const std::string& path) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }

  // Make sure the extension path exists, and is writable.
  if (!pathExists(path) || !isWritable(path)) {
    return Status(1, "Extension socket not availabe: " + path);
  }

  ExtensionStatus ext_status;
  try {
    auto client = EXClient(path);
    client.get()->ping(ext_status);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return Status(ext_status.code, ext_status.message);
}

Status getExtensions(ExtensionList& extensions) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return getExtensions(FLAGS_extensions_socket, extensions);
}

Status getExtensions(const std::string& manager_path,
                     ExtensionList& extensions) {
  // Make sure the extension path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  InternalExtensionList ext_list;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->extensions(ext_list);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Add the extension manager to the list called (core).
  extensions.insert(std::make_pair(0, ExtensionInfo("core")));

  // Convert from Thrift-internal list type to RouteUUID/ExtenionInfo type.
  for (const auto& extension : ext_list) {
    extensions[extension.first] = extension.second;
  }

  return Status(0, "OK");
}

Status callExtension(const RouteUUID uuid,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return callExtension(
      getExtensionSocket(uuid), registry, item, request, response);
}

Status callExtension(const std::string& extension_path,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  // Make sure the extension manager path exists, and is writable.
  if (!pathExists(extension_path) || !isWritable(extension_path)) {
    return Status(1, "Extension socket not availabe: " + extension_path);
  }

  ExtensionResponse ext_response;
  try {
    auto client = EXClient(extension_path);
    client.get()->call(ext_response, registry, item, request);
  }
  catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Convert from Thrift-internal list type to PluginResponse type.
  if (ext_response.status.code == ExtensionCode::EXT_SUCCESS) {
    for (const auto& item : ext_response.response) {
      response.push_back(item);
    }
  }
  return Status(ext_response.status.code, ext_response.status.message);
}

Status startExtensionWatcher(const std::string& manager_path,
                             size_t interval,
                             bool fatal) {
  // Make sure the extension manager path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionWatcher>(manager_path, interval, fatal));
  return Status(0, "OK");
}

Status startExtensionManager() {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return startExtensionManager(FLAGS_extensions_socket);
}

Status startExtensionManager(const std::string& manager_path) {
  // Check if the socket location exists.
  if (pathExists(manager_path).ok()) {
    if (!isWritable(manager_path).ok()) {
      return Status(1, "Cannot write extension socket: " + manager_path);
    }

    if (!remove(manager_path).ok()) {
      return Status(1, "Cannot remove extension socket: " + manager_path);
    }
  }

  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionManagerWatcher>(manager_path,
                                                kWatcherMLatency));

  // Start the extension manager thread.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));
  return Status(0, "OK");
}
}
