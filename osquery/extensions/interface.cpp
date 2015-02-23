/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/extensions/interface.h"

using namespace osquery::extensions;

namespace osquery {
namespace extensions {

void ExtensionHandler::ping(ExtensionStatus& _return) {
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "pong";
  _return.uuid = uuid_;
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
  _return.status.uuid = uuid_;

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
    _return.uuid = 0;
    return;
  }

  // On success return the uuid of the now de-registered extension.
  Registry::removeBroadcast(uuid);
  extensions_.erase(uuid);
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.uuid = uuid;
}

void ExtensionManagerHandler::query(ExtensionResponse& _return,
                                    const std::string& sql) {
  QueryData results;
  auto status = osquery::query(sql, results);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();
  _return.status.uuid = uuid_;

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
  _return.status.uuid = uuid_;

  if (status.ok()) {
    for (const auto& column : columns) {
      _return.response.push_back({{column.first, column.second}});
    }
  }
}

void ExtensionManagerHandler::refresh() {
  std::vector<RouteUUID> removed_routes;
  const auto uuids = Registry::routeUUIDs();
  for (const auto& ext : extensions_) {
    // Find extension UUIDs that have gone away.
    if (std::find(uuids.begin(), uuids.end(), ext.first) == uuids.end()) {
      removed_routes.push_back(ext.first);
    }
  }

  // Remove each from the manager's list of extension metadata.
  for (const auto& uuid : removed_routes) {
    extensions_.erase(uuid);
  }
}

void ExtensionManagerHandler::extensions(InternalExtensionList& _return) {
  refresh();
  _return = extensions_;
}

bool ExtensionManagerHandler::exists(const std::string& name) {
  refresh();

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
  OSQUERY_THRIFT_POINTER::shared_ptr<ExtensionHandler> handler(
      new ExtensionHandler(uuid_));
  OSQUERY_THRIFT_POINTER::shared_ptr<TProcessor> processor(
      new ExtensionProcessor(handler));
  OSQUERY_THRIFT_POINTER::shared_ptr<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  OSQUERY_THRIFT_POINTER::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  OSQUERY_THRIFT_POINTER::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  OSQUERY_THRIFT_POINTER::shared_ptr<ThreadManager> threadManager =
      ThreadManager::newSimpleThreadManager(FLAGS_worker_threads);
  OSQUERY_THRIFT_POINTER::shared_ptr<PosixThreadFactory> threadFactory =
      OSQUERY_THRIFT_POINTER::shared_ptr<PosixThreadFactory>(
          new PosixThreadFactory());
  threadManager->threadFactory(threadFactory);
  threadManager->start();

  // Start the Thrift server's run loop.
  try {
    VLOG(1) << "Extension service starting: " << socket_path;
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
  OSQUERY_THRIFT_POINTER::shared_ptr<ExtensionManagerHandler> handler(
      new ExtensionManagerHandler());
  OSQUERY_THRIFT_POINTER::shared_ptr<TProcessor> processor(
      new ExtensionManagerProcessor(handler));
  OSQUERY_THRIFT_POINTER::shared_ptr<TServerTransport> serverTransport(
      new TServerSocket(socket_path));
  OSQUERY_THRIFT_POINTER::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  OSQUERY_THRIFT_POINTER::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  OSQUERY_THRIFT_POINTER::shared_ptr<ThreadManager> threadManager =
      ThreadManager::newSimpleThreadManager(FLAGS_worker_threads);
  OSQUERY_THRIFT_POINTER::shared_ptr<PosixThreadFactory> threadFactory =
      OSQUERY_THRIFT_POINTER::shared_ptr<PosixThreadFactory>(
          new PosixThreadFactory());
  threadManager->threadFactory(threadFactory);
  threadManager->start();

  // Start the Thrift server's run loop.
  try {
    VLOG(1) << "Extension manager service starting: " << socket_path;
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
}