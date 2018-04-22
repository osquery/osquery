/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/system.h>

#include <thrift/concurrency/ThreadManager.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TBufferTransports.h>

#ifdef WIN32
#include <thrift/transport/TPipe.h>
#include <thrift/transport/TPipeServer.h>
#else
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TSocket.h>
#endif

#include "Extension.h"
#include "ExtensionManager.h"

#include "osquery/extensions/interface.h"

namespace osquery {

using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;
using namespace apache::thrift::concurrency;

#ifdef WIN32
using TPlatformServerSocket = TPipeServer;
using TPlatformSocket = TPipe;
#else
using TPlatformServerSocket = TServerSocket;
using TPlatformSocket = TSocket;
#endif

class ExtensionHandler : virtual public extensions::ExtensionIf,
                         public ExtensionInterface {
 public:
  ExtensionHandler() : ExtensionInterface(0) {}
  explicit ExtensionHandler(RouteUUID uuid) : ExtensionInterface(uuid) {}

 public:
  using ExtensionInterface::ping;
  void ping(extensions::ExtensionStatus& _return) override;

  using ExtensionInterface::call;
  void call(extensions::ExtensionResponse& _return,
            const std::string& registry,
            const std::string& item,
            const extensions::ExtensionPluginRequest& request) override;

  using ExtensionInterface::shutdown;
  void shutdown() override;

 protected:
  /// UUID accessor.
  RouteUUID getUUID() const;
};

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4250)
#endif

class ExtensionManagerHandler : virtual public extensions::ExtensionManagerIf,
                                public ExtensionManagerInterface,
                                public ExtensionHandler {
 public:
  ExtensionManagerHandler() = default;

 public:
  using ExtensionManagerInterface::extensions;
  void extensions(extensions::InternalExtensionList& _return) override;

  using ExtensionManagerInterface::options;
  void options(extensions::InternalOptionList& _return) override;

  using ExtensionManagerInterface::registerExtension;
  void registerExtension(
      extensions::ExtensionStatus& _return,
      const extensions::InternalExtensionInfo& info,
      const extensions::ExtensionRegistry& registry) override;

  using ExtensionManagerInterface::deregisterExtension;
  void deregisterExtension(extensions::ExtensionStatus& _return,
                           const extensions::ExtensionRouteUUID uuid) override;

  using ExtensionManagerInterface::query;
  void query(extensions::ExtensionResponse& _return,
             const std::string& sql) override;

  using ExtensionManagerInterface::getQueryColumns;
  void getQueryColumns(extensions::ExtensionResponse& _return,
                       const std::string& sql) override;

 public:
  using ExtensionHandler::ping;
  using ExtensionHandler::call;
  using ExtensionHandler::shutdown;
};

#ifdef WIN32
#pragma warning(pop)
#endif

struct ImplExtensionRunner {
  std::shared_ptr<TServerTransport> transport;
  std::shared_ptr<TThreadedServer> server;
  std::shared_ptr<TProcessor> processor;
};

struct ImplExtensionClient {
  std::shared_ptr<extensions::ExtensionClient> e;
  std::shared_ptr<extensions::ExtensionManagerClient> em;

  std::shared_ptr<TBufferedTransport> transport;
  std::shared_ptr<TPlatformSocket> socket;
};

void ExtensionHandler::ping(extensions::ExtensionStatus& _return) {
  auto s = ExtensionInterface::ping();
  _return.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
  _return.uuid = s.getCode();
  _return.message = s.getMessage();
}

void ExtensionHandler::call(extensions::ExtensionResponse& _return,
                            const std::string& registry,
                            const std::string& item,
                            const extensions::ExtensionPluginRequest& request) {
  PluginRequest plugin_request;
  for (const auto& request_item : request) {
    // Create a PluginRequest from an ExtensionPluginRequest.
    plugin_request[request_item.first] = request_item.second;
  }

  PluginResponse response;
  auto s = ExtensionInterface::call(registry, item, plugin_request, response);
  _return.status.code = s.getCode();
  _return.status.message = s.getMessage();
  _return.status.uuid = getUUID();

  if (s.ok()) {
    for (const auto& response_item : response) {
      // Translate a PluginResponse to an ExtensionPluginResponse.
      _return.response.push_back(response_item);
    }
  }
}

void ExtensionHandler::shutdown() {}

RouteUUID ExtensionHandler::getUUID() const {
  return uuid_;
}

void ExtensionManagerHandler::extensions(
    extensions::InternalExtensionList& _return) {
  //_return = ExtensionManagerInterface::extensions();
  auto extensions = ExtensionManagerInterface::extensions();
  for (const auto& extension : extensions) {
    auto& ext = _return[extension.first];
    ext.min_sdk_version = extension.second.min_sdk_version;
    ext.version = extension.second.version;
    ext.sdk_version = extension.second.sdk_version;
    ext.name = extension.second.name;
  }
}

void ExtensionManagerHandler::options(extensions::InternalOptionList& _return) {
  auto options = ExtensionManagerInterface::options();
  for (const auto& option : options) {
    _return[option.first].value = option.second.value;
    _return[option.first].default_value = option.second.default_value;
    _return[option.first].type = option.second.type;
  }
}

void ExtensionManagerHandler::registerExtension(
    extensions::ExtensionStatus& _return,
    const extensions::InternalExtensionInfo& info,
    const extensions::ExtensionRegistry& registry) {
  extensions::ExtensionRegistry er;
  for (const auto& rt : registry) {
    er[rt.first] = rt.second;
  }

  RouteUUID uuid;
  auto s = ExtensionManagerInterface::registerExtension(
      {info.name, info.version, info.sdk_version, info.min_sdk_version},
      er,
      uuid);
  _return.message = s.getMessage();
  if (s.ok()) {
    _return.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
    _return.uuid = uuid;
  } else {
    _return.code = (int)extensions::ExtensionCode::EXT_FAILED;
  }
}

void ExtensionManagerHandler::deregisterExtension(
    extensions::ExtensionStatus& _return,
    const extensions::ExtensionRouteUUID uuid) {
  auto s = ExtensionManagerInterface::deregisterExtension(uuid);
  _return.message = s.getMessage();
  if (s.ok()) {
    _return.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
    _return.uuid = getUUID();
  } else {
    _return.code = (int)extensions::ExtensionCode::EXT_FAILED;
  }
}

void ExtensionManagerHandler::query(extensions::ExtensionResponse& _return,
                                    const std::string& sql) {
  QueryData qd;
  auto s = ExtensionManagerInterface::query(sql, qd);
  for (auto& row : qd) {
    _return.response.emplace_back(std::move(row));
  }
  _return.status.message = s.getMessage();
  if (s.ok()) {
    _return.status.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
    _return.status.uuid = getUUID();
  } else {
    _return.status.code = (int)extensions::ExtensionCode::EXT_FAILED;
  }
}

void ExtensionManagerHandler::getQueryColumns(
    extensions::ExtensionResponse& _return, const std::string& sql) {
  QueryData qd;
  auto s = ExtensionManagerInterface::getQueryColumns(sql, qd);
  for (auto& row : qd) {
    _return.response.emplace_back(std::move(row));
  }
  _return.status.message = s.getMessage();
  if (s.ok()) {
    _return.status.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
    _return.status.uuid = getUUID();
  } else {
    _return.status.code = (int)extensions::ExtensionCode::EXT_FAILED;
  }
}

ExtensionRunnerInterface::~ExtensionRunnerInterface() {
  removePath(path_);
};

ExtensionRunnerInterface::ExtensionRunnerInterface()
    : server_{std::make_unique<ImplExtensionRunner>()} {}

void ExtensionRunnerInterface::serve() {
  // Start the Thrift server's run loop.
  server_->server->serve();
}

void ExtensionRunnerInterface::connect() {
  server_->transport = std::make_shared<TPlatformServerSocket>(path_);

  // Construct the service's transport, protocol, thread pool.
  auto transport_fac = std::make_shared<TBufferedTransportFactory>();
  auto protocol_fac = std::make_shared<TBinaryProtocolFactory>();

  server_->server = std::make_shared<TThreadedServer>(
      server_->processor, server_->transport, transport_fac, protocol_fac);
}

void ExtensionRunnerInterface::init(RouteUUID uuid, bool manager) {
  manager_ = manager;

  // Create the thrift instances.
  if (!manager_) {
    auto handler = std::make_shared<ExtensionHandler>(uuid);
    server_->processor =
        std::make_shared<extensions::ExtensionProcessor>(handler);
  } else {
    auto handler = std::make_shared<ExtensionManagerHandler>();
    server_->processor =
        std::make_shared<extensions::ExtensionManagerProcessor>(handler);
  }
}

void ExtensionRunnerInterface::stopServer() {
  // In most cases the service thread has started before the stop request.
  if (server_->server != nullptr) {
    server_->server->stop();
  }
}

void ExtensionRunnerInterface::stopServerManager() {
  if (server_->server != nullptr) {
    removeStalePaths(path_);
  }
}

void ExtensionClientCore::init(const std::string& path, bool manager) {
  path_ = path;
  manager_ = manager;

  client_ = std::make_unique<ImplExtensionClient>();
  client_->socket = std::make_shared<TPlatformSocket>(path);
  client_->transport = std::make_shared<TBufferedTransport>(client_->socket);
  auto protocol = std::make_shared<TBinaryProtocol>(client_->transport);

  if (!manager_) {
    client_->e = std::make_shared<extensions::ExtensionClient>(protocol);
  } else {
    client_->em =
        std::make_shared<extensions::ExtensionManagerClient>(protocol);
  }

  (void)client_->transport->open();
}

ExtensionClientCore::~ExtensionClientCore() {
  try {
    client_->transport->close();
  } catch (const std::exception& /* e */) {
    // The transport/socket may have exited.
  }
}

void ExtensionClientCore::setTimeouts(size_t timeouts) {
#if !defined(WIN32)
  // Windows TPipe does not support timeouts.
  client_->socket->setRecvTimeout(timeouts);
  client_->socket->setSendTimeout(timeouts);
#endif
}

bool ExtensionClientCore::manager() {
  return manager_;
}

ExtensionClient::ExtensionClient(const std::string& path, size_t timeout) {
  init(path, false);
  setTimeouts(timeout);
}

ExtensionManagerClient::ExtensionManagerClient(const std::string& path,
                                               size_t timeout) {
  init(path, true);
  setTimeouts(timeout);
}

Status ExtensionClient::ping() {
  extensions::ExtensionStatus status;
  auto client = manager() ? client_->em : client_->e;
  client->ping(status);
  if (status.code != (int)extensions::ExtensionCode::EXT_FAILED) {
    return Status(0, status.message);
  }
  return Status(1);
}

Status ExtensionClient::call(const std::string& registry,
                             const std::string& item,
                             const PluginRequest& request,
                             PluginResponse& response) {
  extensions::ExtensionResponse er;
  auto client = manager() ? client_->em : client_->e;
  client->call(er, registry, item, request);
  for (const auto& r : er.response) {
    response.push_back(r);
  }

  return Status(er.status.code, er.status.message);
}

void ExtensionClient::shutdown() {
  auto client = manager() ? client_->em : client_->e;
  client->shutdown();
}

ExtensionList ExtensionManagerClient::extensions() {
  ExtensionList el;
  extensions::InternalExtensionList iel;
  client_->em->extensions(iel);
  for (const auto& extension : iel) {
    auto& ext = el[extension.first];
    ext.min_sdk_version = extension.second.min_sdk_version;
    ext.version = extension.second.version;
    ext.sdk_version = extension.second.sdk_version;
    ext.name = extension.second.name;
  }
  return el;
}

OptionList ExtensionManagerClient::options() {
  OptionList ol;
  extensions::InternalOptionList iol;
  client_->em->options(iol);
  for (const auto& option : iol) {
    auto& opt = option.second;
    ol[option.first] = {opt.value, opt.default_value, opt.type};
  }
  return ol;
}

Status ExtensionManagerClient::registerExtension(
    const ExtensionInfo& info,
    const extensions::ExtensionRegistry& registry,
    RouteUUID& uuid) {
  extensions::InternalExtensionInfo iei;
  iei.name = info.name;
  iei.version = info.version;
  iei.sdk_version = info.sdk_version;
  iei.min_sdk_version = info.min_sdk_version;
  extensions::ExtensionStatus status;
  client_->em->registerExtension(status, iei, registry);
  uuid = status.uuid;
  return Status(status.code, status.message);
}

Status ExtensionManagerClient::query(const std::string& sql, QueryData& qd) {
  extensions::ExtensionResponse er;
  client_->em->query(er, sql);
  for (const auto& row : er.response) {
    qd.push_back(row);
  }

  return Status();
}

Status ExtensionManagerClient::getQueryColumns(const std::string& sql,
                                               QueryData& qd) {
  extensions::ExtensionResponse er;
  client_->em->getQueryColumns(er, sql);
  for (const auto& row : er.response) {
    qd.push_back(row);
  }

  return Status(er.status.code, er.status.message);
}

Status ExtensionManagerClient::deregisterExtension(RouteUUID uuid) {
  extensions::ExtensionStatus status;
  client_->em->deregisterExtension(status, uuid);
  return Status(status.code, status.message);
}

ExtensionClient::~ExtensionClient() {}

ExtensionManagerClient::~ExtensionManagerClient() {}
} // namespace osquery
