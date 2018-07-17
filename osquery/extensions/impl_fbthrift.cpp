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

#include <thrift/lib/cpp/async/TAsyncSocket.h>
#include <thrift/lib/cpp2/async/HeaderClientChannel.h>
#include <thrift/lib/cpp2/server/ThriftServer.h>

// Include intermediate Thrift-generated interface definitions.
#include "osquery/gen-cpp2/Extension.h"
#include "osquery/gen-cpp2/ExtensionManager.h"

#include "osquery/extensions/interface.h"

namespace osquery {

using namespace extensions;

class ExtensionHandler : virtual public extensions::ExtensionSvIf,
                         public ExtensionInterface {
 public:
  ExtensionHandler() : ExtensionInterface(0) {}
  explicit ExtensionHandler(RouteUUID uuid) : ExtensionInterface(uuid) {}

 public:
  using ExtensionInterface::ping;
  void ping(ExtensionStatus& _return) override;

  using ExtensionInterface::call;
  void call(ExtensionResponse& _return,
            const std::string& registry,
            const std::string& item,
            const ExtensionPluginRequest& request) override;

  using ExtensionInterface::shutdown;
  void shutdown() override;

 protected:
  /// UUID accessor.
  RouteUUID getUUID() const;
};

class ExtensionManagerHandler : virtual public extensions::ExtensionManagerSvIf,
                                public ExtensionManagerInterface,
                                public ExtensionHandler {
 public:
  ExtensionManagerHandler() = default;

 public:
  using ExtensionManagerInterface::extensions;
  void extensions(InternalExtensionList& _return) override;

  using ExtensionManagerInterface::options;
  void options(InternalOptionList& _return) override;

  using ExtensionManagerInterface::registerExtension;
  void registerExtension(ExtensionStatus& _return,
                         const InternalExtensionInfo& info,
                         const ExtensionRegistry& registry) override;

  using ExtensionManagerInterface::deregisterExtension;
  void deregisterExtension(ExtensionStatus& _return,
                           const ExtensionRouteUUID uuid) override;

  using ExtensionManagerInterface::query;
  void query(ExtensionResponse& _return, const std::string& sql) override;

  using ExtensionManagerInterface::getQueryColumns;
  void getQueryColumns(ExtensionResponse& _return,
                       const std::string& sql) override;
};

struct ImplExtensionRunner {
  std::unique_ptr<apache::thrift::ThriftServer> server;
  std::shared_ptr<ExtensionHandler> handler;

  /// Raw socket descriptor.
  int sd;
};

struct ImplExtensionClient {
  folly::EventBase base;

  std::unique_ptr<extensions::ExtensionAsyncClient> e;
  std::unique_ptr<extensions::ExtensionManagerAsyncClient> em;

  /// Raw socket descriptor.
  int sd;
};

void ExtensionHandler::ping(ExtensionStatus& _return) {
  auto s = ExtensionInterface::ping();
  _return.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
  _return.uuid = s.getCode();
  _return.message = s.getMessage();
}

void ExtensionHandler::call(ExtensionResponse& _return,
                            const std::string& registry,
                            const std::string& item,
                            const ExtensionPluginRequest& request) {
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

void ExtensionManagerHandler::extensions(InternalExtensionList& _return) {
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

void ExtensionManagerHandler::options(InternalOptionList& _return) {
  auto options = ExtensionManagerInterface::options();
  for (const auto& option : options) {
    _return[option.first].value = option.second.value;
    _return[option.first].default_value = option.second.default_value;
    _return[option.first].type = option.second.type;
  }
}

void ExtensionManagerHandler::registerExtension(
    ExtensionStatus& _return,
    const InternalExtensionInfo& info,
    const ExtensionRegistry& registry) {
  ExtensionRegistry er;
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
    ExtensionStatus& _return, const ExtensionRouteUUID uuid) {
  auto s = ExtensionManagerInterface::deregisterExtension(uuid);
  _return.message = s.getMessage();
  if (s.ok()) {
    _return.code = (int)extensions::ExtensionCode::EXT_SUCCESS;
    _return.uuid = getUUID();
  } else {
    _return.code = (int)extensions::ExtensionCode::EXT_FAILED;
  }
}

void ExtensionManagerHandler::query(ExtensionResponse& _return,
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

void ExtensionManagerHandler::getQueryColumns(ExtensionResponse& _return,
                                              const std::string& sql) {
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

  if (server_->sd > 0) {
    close(server_->sd);
    server_->sd = 0;
  }
};

ExtensionRunnerInterface::ExtensionRunnerInterface()
    : server_{std::make_unique<ImplExtensionRunner>()} {}

void ExtensionRunnerInterface::serve() {
  // Start the Thrift server's run loop.
  server_->server->serve();
}

void ExtensionRunnerInterface::connect() {
  server_->server = std::make_unique<apache::thrift::ThriftServer>();
  server_->server->setInterface(server_->handler);

  server_->sd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::bind(server_->sd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error("Cannot bind to socket");
  }
  server_->server->useExistingSocket(server_->sd);
}

void ExtensionRunnerInterface::init(RouteUUID uuid, bool manager) {
  manager_ = manager;

  // Create the thrift instances.
  if (!manager_) {
    server_->handler = std::make_shared<ExtensionHandler>(uuid);
  } else {
    server_->handler = std::make_shared<ExtensionManagerHandler>();
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
  client_->sd = socket(AF_UNIX, SOCK_STREAM, 0);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(client_->sd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error("Cannot connect to socket");
  }

  auto tsock(apache::thrift::async::TAsyncSocket::newSocket(&client_->base,
                                                            client_->sd));
  auto channel(apache::thrift::HeaderClientChannel::newChannel(tsock));
  channel->setProtocolId(apache::thrift::protocol::T_BINARY_PROTOCOL);
  channel->setClientType(THRIFT_UNFRAMED_DEPRECATED);

  if (!manager_) {
    client_->e = std::make_unique<ExtensionAsyncClient>(std::move(channel));
  } else {
    client_->em =
        std::make_unique<ExtensionManagerAsyncClient>(std::move(channel));
  }
}

ExtensionClientCore::~ExtensionClientCore() = default;

void ExtensionClientCore::setTimeouts(size_t /* timeouts */) {}

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
  ExtensionStatus status;
  auto client = manager() ? client_->em.get() : client_->e.get();
  client->sync_ping(status);
  if (status.code != (int)extensions::ExtensionCode::EXT_FAILED) {
    return Status(0, status.message);
  }
  return Status(1);
}

Status ExtensionClient::call(const std::string& registry,
                             const std::string& item,
                             const PluginRequest& request,
                             PluginResponse& response) {
  ExtensionResponse er;
  auto client = manager() ? client_->em.get() : client_->e.get();
  client->sync_call(er, registry, item, request);
  for (const auto& r : er.response) {
    response.push_back(r);
  }

  return Status(er.status.code, er.status.message);
}

void ExtensionClient::shutdown() {
  auto client = manager() ? client_->em.get() : client_->e.get();
  client->sync_shutdown();
}

ExtensionList ExtensionManagerClient::extensions() {
  ExtensionList el;
  InternalExtensionList iel;
  client_->em->sync_extensions(iel);
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
  InternalOptionList iol;
  client_->em->sync_options(iol);
  for (const auto& option : iol) {
    auto& opt = option.second;
    ol[option.first] = {opt.value, opt.default_value, opt.type};
  }
  return ol;
}

Status ExtensionManagerClient::registerExtension(
    const ExtensionInfo& info,
    const ExtensionRegistry& registry,
    RouteUUID& uuid) {
  InternalExtensionInfo iei;
  iei.name = info.name;
  iei.version = info.version;
  iei.sdk_version = info.sdk_version;
  iei.min_sdk_version = info.min_sdk_version;
  ExtensionStatus status;
  client_->em->sync_registerExtension(status, iei, registry);
  uuid = status.uuid;
  return Status(status.code, status.message);
}

Status ExtensionManagerClient::query(const std::string& sql, QueryData& qd) {
  ExtensionResponse er;
  client_->em->sync_query(er, sql);
  for (const auto& row : er.response) {
    qd.push_back(row);
  }

  return Status();
}

Status ExtensionManagerClient::getQueryColumns(const std::string& sql,
                                               QueryData& qd) {
  ExtensionResponse er;
  client_->em->sync_getQueryColumns(er, sql);
  for (const auto& row : er.response) {
    qd.push_back(row);
  }

  return Status(er.status.code, er.status.message);
}

Status ExtensionManagerClient::deregisterExtension(RouteUUID uuid) {
  ExtensionStatus status;
  client_->em->sync_deregisterExtension(status, uuid);
  return Status(status.code, status.message);
}

ExtensionClient::~ExtensionClient() {}

ExtensionManagerClient::~ExtensionManagerClient() {}
} // namespace osquery
