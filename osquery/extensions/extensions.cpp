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
#include <thrift/lib/cpp/protocol/TBinaryProtocol.h>
#include <thrift/lib/cpp/server/example/TSimpleServer.h>
#include <thrift/lib/cpp/transport/TServerSocket.h>
#include <thrift/lib/cpp/transport/TBufferTransports.h>
#include <thrift/lib/cpp/transport/TSocket.h>
#define _SHARED_PTR std::shared_ptr
#else
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>
#define _SHARED_PTR boost::shared_ptr
#endif

#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace osquery::extensions;

namespace osquery {

FLAG(bool, disable_extensions, false, "Disable extension API");

FLAG(string,
     extensions_socket,
     "/var/osquery/osquery.em",
     "Path to the extensions UNIX domain socket")

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
    LOG(WARNING) << "Could not add extension (" << uuid
                 << ") broadcast to registry";
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Failed adding registry broadcase";
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

bool ExtensionManagerHandler::exists(const std::string& name) {
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
  _SHARED_PTR<ExtensionHandler> handler(new ExtensionHandler());
  _SHARED_PTR<TProcessor> processor(new ExtensionProcessor(handler));
  _SHARED_PTR<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  _SHARED_PTR<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  _SHARED_PTR<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  // Start the Thrift server's run loop.
  try {
    TSimpleServer server(
        processor, serverTransport, transportFactory, protocolFactory);
    server.serve();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Cannot start extension handler (" << socket_path << ") ("
               << e.what() << ")";
    throw e;
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
  _SHARED_PTR<ExtensionManagerHandler> handler(
      new ExtensionManagerHandler());
  _SHARED_PTR<TProcessor> processor(
      new ExtensionManagerProcessor(handler));
  _SHARED_PTR<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  _SHARED_PTR<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  _SHARED_PTR<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  // Start the Thrift server's run loop.
  try {
    TSimpleServer server(
        processor, serverTransport, transportFactory, protocolFactory);
    server.serve();
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extensions disabled: cannot start extension manager ("
                 << socket_path << ") (" << e.what() << ")";
  }
}

void ExtensionWatcher::enter() {
  // Watch the manager, if the socket is removed then the extension will die.
  _SHARED_PTR<TSocket> socket(new TSocket(manager_path_));
  _SHARED_PTR<TTransport> transport(new TBufferedTransport(socket));
  _SHARED_PTR<TProtocol> protocol(new TBinaryProtocol(transport));

  // Open a long-lived client to the extension manager.
  ExtensionManagerClient client(protocol);
  transport->open();

  ExtensionStatus status;
  while (true) {
    // Ping the extension manager until it goes down.
    client.ping(status);
    if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
      transport->close();
      exitFatal();
    }
    interruptableSleep(interval_);
  }

  // Code will never reach this socket close.
  transport->close();
}

void ExtensionWatcher::exitFatal() {
  // Exit the extension.
  // Not yet implemented.
}

#ifdef OSQUERY_EXTENSION_NAME
Status startExtension() {
  // No assumptions about how the extensions logs, the first action is to
  // start the extension's registry.
  Registry::setUp();

  auto status = startExtensionWatcher(FLAGS_extensions_socket, 3000, true);
  if (status.ok()) {
    status = startExtension(FLAGS_extensions_socket,
                            OSQUERY_EXTENSION_NAME,
                            OSQUERY_EXTENSION_VERSION,
                            OSQUERY_SDK_VERSION);
  }
  return status;
}
#endif

Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& sdk_version) {
  // Make sure the extension manager path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not availabe: " + manager_path);
  }

  // Open a socket to the extension manager to register.
  _SHARED_PTR<TSocket> socket(new TSocket(manager_path));
  _SHARED_PTR<TTransport> transport(new TBufferedTransport(socket));
  _SHARED_PTR<TProtocol> protocol(new TBinaryProtocol(transport));

  // The Registry broadcast is used as the ExtensionRegistry.
  auto broadcast = Registry::getBroadcast();

  InternalExtensionInfo info;
  info.name = name;
  info.version = version;
  info.sdk_version = sdk_version;

  // Register the extension's registry broadcast with the manager.
  ExtensionManagerClient client(protocol);
  ExtensionStatus status;
  try {
    transport->open();
    client.registerExtension(status, info, broadcast);
    transport->close();
  }
  catch (const std::exception& e) {
    return Status(1, "Extension register failed: " + std::string(e.what()));
  }

  if (status.code != ExtensionCode::EXT_SUCCESS) {
    return Status(status.code, status.message);
  }

  // Start the extension's Thrift server
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionRunner>(manager_path, status.uuid));
  return Status(0, std::to_string(status.uuid));
}

Status pingExtension(const std::string& path) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }

  // Make sure the extension path exists, and is writable.
  if (!pathExists(path) || !isWritable(path)) {
    return Status(1, "Extension socket not availabe: " + path);
  }

  // Open a socket to the extension.
  _SHARED_PTR<TSocket> socket(new TSocket(path));
  _SHARED_PTR<TTransport> transport(new TBufferedTransport(socket));
  _SHARED_PTR<TProtocol> protocol(new TBinaryProtocol(transport));

  ExtensionClient client(protocol);
  ExtensionStatus ext_status;
  try {
    transport->open();
    client.ping(ext_status);
    transport->close();
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

  // Open a socket to the extension.
  _SHARED_PTR<TSocket> socket(new TSocket(manager_path));
  _SHARED_PTR<TTransport> transport(new TBufferedTransport(socket));
  _SHARED_PTR<TProtocol> protocol(new TBinaryProtocol(transport));

  ExtensionManagerClient client(protocol);
  InternalExtensionList ext_list;
  try {
    transport->open();
    client.extensions(ext_list);
    transport->close();
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

  // Open a socket to the extension manager to register.
  _SHARED_PTR<TSocket> socket(new TSocket(extension_path));
  _SHARED_PTR<TTransport> transport(new TBufferedTransport(socket));
  _SHARED_PTR<TProtocol> protocol(new TBinaryProtocol(transport));

  ExtensionClient client(protocol);
  ExtensionResponse ext_response;
  try {
    transport->open();
    client.call(ext_response, registry, item, request);
    transport->close();
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

  // Start the extension manager thread.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));
  return Status(0, "OK");
}
}
