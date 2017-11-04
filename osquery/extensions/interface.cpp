/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/extensions/interface.h"

using namespace osquery::extensions;

using chrono_clock = std::chrono::high_resolution_clock;

namespace osquery {
namespace extensions {

const std::vector<std::string> kSDKVersionChanges = {
    {"1.7.7"},
};

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
  auto local_item = RegistryFactory::get().getAlias(registry, item);
  if (local_item.empty()) {
    // Extensions may not know about active (non-option based registries).
    local_item = RegistryFactory::get().getActive(registry);
  }

  PluginResponse response;
  PluginRequest plugin_request;
  for (const auto& request_item : request) {
    // Create a PluginRequest from an ExtensionPluginRequest.
    plugin_request[request_item.first] = request_item.second;
  }

  auto status =
      RegistryFactory::call(registry, local_item, plugin_request, response);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();
  _return.status.uuid = uuid_;
  if (status.ok()) {
    for (const auto& response_item : response) {
      // Translate a PluginResponse to an ExtensionPluginResponse.
      _return.response.push_back(response_item);
    }
  }
}

void ExtensionHandler::shutdown() {
  // Request a graceful shutdown of the Thrift listener.
  VLOG(1) << "Extension " << uuid_ << " requested shutdown";
  Initializer::requestShutdown(EXIT_SUCCESS);
}

/**
 * @brief Updates the Thrift server output to be VLOG
 *
 * On Windows, the thrift server will output to stdout, which displays
 * messages to the user on exiting the client. This function is used
 * instead of the default output for thrift.
 *
 * @param msg The text to be logged
 */
void thriftLoggingOutput(const char* msg) {
  VLOG(1) << "Thrift message: " << msg;
}

ExtensionManagerHandler::ExtensionManagerHandler() {
  GlobalOutput.setOutputFunction(thriftLoggingOutput);
}

void ExtensionManagerHandler::extensions(InternalExtensionList& _return) {
  refresh();

  ReadLock lock(extensions_mutex_);
  _return = extensions_;
}

void ExtensionManagerHandler::options(InternalOptionList& _return) {
  auto flags = Flag::flags();
  for (const auto& flag : flags) {
    _return[flag.first].value = flag.second.value;
    _return[flag.first].default_value = flag.second.default_value;
    _return[flag.first].type = flag.second.type;
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

  // Enforce API change requirements.
  for (const auto& change : kSDKVersionChanges) {
    if (!versionAtLeast(change, info.sdk_version)) {
      LOG(WARNING) << "Could not add extension " << info.name
                   << ": incompatible extension SDK " << info.sdk_version;
      _return.code = ExtensionCode::EXT_FAILED;
      _return.message = "Incompatible extension SDK version";
      return;
    }
  }

  // srand must be called in the active thread on Windows due to thread saftey
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    std::srand(static_cast<unsigned int>(
        chrono_clock::now().time_since_epoch().count()));
  }
  // Every call to registerExtension is assigned a new RouteUUID.
  RouteUUID uuid = static_cast<uint16_t>(rand());
  VLOG(1) << "Registering extension (" << info.name << ", " << uuid
          << ", version=" << info.version << ", sdk=" << info.sdk_version
          << ")";

  if (!RegistryFactory::get().addBroadcast(uuid, registry).ok()) {
    LOG(WARNING) << "Could not add extension " << info.name
                 << ": invalid extension registry";
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Failed adding registry broadcast";
    return;
  }

  WriteLock lock(extensions_mutex_);
  extensions_[uuid] = info;
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "OK";
  _return.uuid = uuid;
}

void ExtensionManagerHandler::deregisterExtension(
    ExtensionStatus& _return, const ExtensionRouteUUID uuid) {
  {
    ReadLock lock(extensions_mutex_);
    if (extensions_.count(uuid) == 0) {
      _return.code = ExtensionCode::EXT_FAILED;
      _return.message = "No extension UUID registered";
      _return.uuid = 0;
      return;
    }
  }

  // On success return the uuid of the now de-registered extension.
  RegistryFactory::get().removeBroadcast(uuid);

  WriteLock lock(extensions_mutex_);
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
  TableColumns columns;
  auto status = osquery::getQueryColumns(sql, columns);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();
  _return.status.uuid = uuid_;

  if (status.ok()) {
    for (const auto& col : columns) {
      _return.response.push_back(
          {{std::get<0>(col), columnTypeName(std::get<1>(col))}});
    }
  }
}

void ExtensionManagerHandler::refresh() {
  std::vector<RouteUUID> removed_routes;
  const auto uuids = RegistryFactory::get().routeUUIDs();

  WriteLock lock(extensions_mutex_);
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

bool ExtensionManagerHandler::exists(const std::string& name) {
  refresh();

  // Search the remaining extension list for duplicates.
  ReadLock lock(extensions_mutex_);
  for (const auto& extension : extensions_) {
    if (extension.second.name == name) {
      return true;
    }
  }
  return false;
}
} // namespace extensions

ExtensionRunner::ExtensionRunner(const std::string& manager_path,
                                 RouteUUID uuid)
    : ExtensionRunnerCore(""), uuid_(uuid) {
  path_ = getExtensionSocket(uuid, manager_path);
}

ExtensionRunnerCore::~ExtensionRunnerCore() {
  removePath(path_);
}

void ExtensionRunnerCore::stop() {
  {
    WriteLock lock(service_start_);
    service_stopping_ = true;
    if (transport_ != nullptr) {
      // This is an opportunity to interrupt the transport listens.
    }
  }

  // In most cases the service thread has started before the stop request.
  if (server_ != nullptr) {
    server_->stop();
  }
}

inline void removeStalePaths(const std::string& manager) {
  std::vector<std::string> paths;
  // Attempt to remove all stale extension sockets.
  resolveFilePattern(manager + ".*", paths);
  for (const auto& path : paths) {
    removePath(path);
  }
}

void ExtensionRunnerCore::startServer(TProcessorRef processor) {
  {
    WriteLock lock(service_start_);
    // A request to stop the service may occur before the thread starts.
    if (service_stopping_) {
      return;
    }

    transport_ = TServerTransportRef(new TPlatformServerSocket(path_));

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      // Before starting and after stopping the manager, remove stale sockets.
      // This is not relevant in Windows
      removeStalePaths(path_);
    }

    // Construct the service's transport, protocol, thread pool.
    auto transport_fac = TTransportFactoryRef(new TBufferedTransportFactory());
    auto protocol_fac = TProtocolFactoryRef(new TBinaryProtocolFactory());

    // Start the Thrift server's run loop.
    server_ = TThreadedServerRef(new TThreadedServer(
        processor, transport_, transport_fac, protocol_fac));
  }

  server_->serve();
}

RouteUUID ExtensionRunner::getUUID() const {
  return uuid_;
}

void ExtensionRunner::start() {
  // Create the thrift instances.
  auto handler = ExtensionHandlerRef(new ExtensionHandler(uuid_));
  auto processor = TProcessorRef(new ExtensionProcessor(handler));

  VLOG(1) << "Extension service starting: " << path_;
  try {
    startServer(processor);
  } catch (const std::exception& e) {
    LOG(ERROR) << "Cannot start extension handler: " << path_ << " ("
               << e.what() << ")";
  }
}

ExtensionManagerRunner::~ExtensionManagerRunner() {
  // Only attempt to remove stale paths if the server was started.
  WriteLock lock(service_start_);
  if (server_ != nullptr) {
    removeStalePaths(path_);
  }
}

void ExtensionManagerRunner::start() {
  // Create the thrift instances.
  auto handler = ExtensionManagerHandlerRef(new ExtensionManagerHandler());
  auto processor = TProcessorRef(new ExtensionManagerProcessor(handler));

  VLOG(1) << "Extension manager service starting: " << path_;
  try {
    startServer(processor);
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extensions disabled: cannot start extension manager ("
                 << path_ << ") (" << e.what() << ")";
  }
}

EXInternal::~EXInternal() {
  try {
    transport_->close();
  } catch (const std::exception& /* e */) {
    // The transport/socket may have exited.
  }
}

void EXInternal::setTimeouts(size_t timeouts) {
#ifndef WIN32
  // Windows TPipe does not support timeouts.
  socket_->setRecvTimeout(timeouts);
  socket_->setSendTimeout(timeouts);
#endif
}

EXClient::EXClient(const std::string& path, size_t timeout)
    : EXInternal(path),
      client_(std::make_shared<extensions::ExtensionClient>(protocol_)) {
  setTimeouts(timeout);
  (void)transport_->open();
}

EXManagerClient::EXManagerClient(const std::string& manager_path,
                                 size_t timeout)
    : EXInternal(manager_path),
      client_(std::make_shared<extensions::ExtensionManagerClient>(protocol_)) {
  setTimeouts(timeout);
  (void)transport_->open();
}

const std::shared_ptr<extensions::ExtensionClient>& EXClient::get() const {
  return client_;
}

const std::shared_ptr<extensions::ExtensionManagerClient>&
EXManagerClient::get() const {
  return client_;
}
} // namespace osquery
