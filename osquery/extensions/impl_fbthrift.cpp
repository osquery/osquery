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

#include "osquery/extensions/interface.h"

#include <thrift/lib/cpp/async/TAsyncSocket.h>
#include <thrift/lib/cpp2/async/HeaderClientChannel.h>
#include <thrift/lib/cpp2/protocol/BinaryProtocol.h>
#include <thrift/lib/cpp2/server/ThriftServer.h>

using namespace osquery::extensions;

namespace osquery {

using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;
using namespace apache::thrift::concurrency;

typedef std::shared_ptr<AsyncProcessorFactory> TProcessorRef;
using TThreadedServerRef = std::shared_ptr<ThriftServer>;

typedef std::shared_ptr<ExtensionHandler> ExtensionHandlerRef;
typedef std::shared_ptr<ExtensionManagerHandler> ExtensionManagerHandlerRef;

struct ImpExtensionRunner {
  TThreadedServerRef server_{nullptr};
  TProcessorRef processor_{nullptr};
};

struct ImpExtensionManagerServer {
  folly::EventBase base_;
};

ExtensionRunnerImpl::~ExtensionRunnerImpl() {
  removePath(path_);

  if (raw_socket_ > 0) {
    close(raw_socket_);
    raw_socket_ = 0;
  }
};

ExtensionRunnerImpl::ExtensionRunnerImpl()
    : server{std::make_unique<ImpExtensionRunner>()} {}

void ExtensionRunnerImpl::serve() {
  // Start the Thrift server's run loop.
  server->server_->serve();
}

void ExtensionRunnerImpl::connect() {
  server->server_ = TThreadedServerRef(new ThriftServer());
  server->server_->setProcessorFactory(server->processor_);

  raw_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (bind(raw_socket_, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error("Cannot bind to socket");
  }
  server->server_->useExistingSocket(raw_socket_);
}

void ExtensionRunnerImpl::init(RouteUUID uuid) {
  // Create the thrift instances.
  auto handler = ExtensionHandlerRef(new ExtensionHandler(uuid));
  server->processor_ =
      std::make_shared<ThriftServerAsyncProcessorFactory<ExtensionHandler>>(
          handler);
}

void ExtensionRunnerImpl::initManager() {
  // Create the thrift instances.
  auto handler = ExtensionManagerHandlerRef(new ExtensionManagerHandler());
  server->processor_ = std::make_shared<
      ThriftServerAsyncProcessorFactory<ExtensionManagerHandler>>(handler);
}

void ExtensionRunnerImpl::stopServer() {
  // In most cases the service thread has started before the stop request.
  if (server->server_ != nullptr) {
    server->server_->stop();
  }
}

void ExtensionRunnerImpl::stopServerManager() {
  if (server->server_ != nullptr) {
    removeStalePaths(path_);
  }
}

EXInternal::EXInternal(const std::string& path)
    : path_(path), server{std::make_unique<ImpExtensionManagerServer>()} {
  raw_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (connect(raw_socket_, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    throw std::runtime_error("Cannot connect to socket");
  }
}

EXInternal::~EXInternal() = default;

void EXInternal::setTimeouts(size_t timeouts) {}

EXClient::EXClient(const std::string& path, size_t timeout) : EXInternal(path) {
  setTimeouts(timeout);
  // client_ = std::make_shared<_Client>(HeaderClientChannel::newChannel(
  //    async::TAsyncSocket::newSocket(&server->base_, raw_socket_)));
}

EXManagerClient::EXManagerClient(const std::string& manager_path,
                                 size_t timeout)
    : EXInternal(manager_path) {
  setTimeouts(timeout);
  // client_ = std::make_shared<_ManagerClient>(HeaderClientChannel::newChannel(
  //    async::TAsyncSocket::newSocket(&server->base_, raw_socket_)));
}

const std::shared_ptr<_Client>& EXClient::get() const {
  return client_;
}

const std::shared_ptr<_ManagerClient>& EXManagerClient::get() const {
  return client_;
}
} // namespace osquery