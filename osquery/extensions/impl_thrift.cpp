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

using namespace osquery::extensions;

namespace osquery {

using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;
using namespace apache::thrift::concurrency;

#ifdef WIN32
typedef TPipe TPlatformSocket;
typedef TPipeServer TPlatformServerSocket;
typedef std::shared_ptr<TPipe> TPlatformSocketRef;
#else
typedef TSocket TPlatformSocket;
typedef TServerSocket TPlatformServerSocket;
typedef std::shared_ptr<TSocket> TPlatformSocketRef;
#endif

typedef std::shared_ptr<TTransport> TTransportRef;
typedef std::shared_ptr<TProtocol> TProtocolRef;
typedef std::shared_ptr<TServerTransport> TServerTransportRef;
typedef std::shared_ptr<TProcessor> TProcessorRef;
typedef std::shared_ptr<TTransportFactory> TTransportFactoryRef;
typedef std::shared_ptr<TProtocolFactory> TProtocolFactoryRef;
using TThreadedServerRef = std::shared_ptr<TThreadedServer>;

typedef std::shared_ptr<ExtensionHandler> ExtensionHandlerRef;
typedef std::shared_ptr<ExtensionManagerHandler> ExtensionManagerHandlerRef;

struct ImpExtensionRunner {
  TServerTransportRef transport_{nullptr};
  TThreadedServerRef server_{nullptr};
  TProcessorRef processor_{nullptr};
};

struct ImpExtensionManagerServer {
  TPlatformSocketRef socket_;
  TTransportRef transport_;
  TProtocolRef protocol_;
};

ExtensionRunnerImpl::~ExtensionRunnerImpl() {
  if (pathExists(path_).ok()) {
    removePath(path_);
  }
};

ExtensionRunnerImpl::ExtensionRunnerImpl()
    : server{std::make_unique<ImpExtensionRunner>()} {}

void ExtensionRunnerImpl::serve() {
  // Start the Thrift server's run loop.
  server->server_->serve();
}

void ExtensionRunnerImpl::connect() {
  server->transport_ = TServerTransportRef(new TPlatformServerSocket(path_));

  // Construct the service's transport, protocol, thread pool.
  auto transport_fac = TTransportFactoryRef(new TBufferedTransportFactory());
  auto protocol_fac = TProtocolFactoryRef(new TBinaryProtocolFactory());

  server->server_ = TThreadedServerRef(new TThreadedServer(
      server->processor_, server->transport_, transport_fac, protocol_fac));
}

void ExtensionRunnerImpl::init(RouteUUID uuid) {
  // Create the thrift instances.
  auto handler = ExtensionHandlerRef(new ExtensionHandler(uuid));
  server->processor_ = TProcessorRef(new ExtensionProcessor(handler));
}

void ExtensionRunnerImpl::initManager() {
  // Create the thrift instances.
  auto handler = ExtensionManagerHandlerRef(new ExtensionManagerHandler());
  server->processor_ = TProcessorRef(new ExtensionManagerProcessor(handler));
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
  server->socket_ = std::make_shared<TPlatformSocket>(path);
  server->transport_ = std::make_shared<TBufferedTransport>(server->socket_);
  server->protocol_ = std::make_shared<TBinaryProtocol>(server->transport_);
}

EXInternal::~EXInternal() {
  try {
    server->transport_->close();
  } catch (const std::exception& /* e */) {
    // The transport/socket may have exited.
  }
}

void EXInternal::setTimeouts(size_t timeouts) {
#if !defined(WIN32)
  // Windows TPipe does not support timeouts.
  server->socket_->setRecvTimeout(timeouts);
  server->socket_->setSendTimeout(timeouts);
#endif
}

EXClient::EXClient(const std::string& path, size_t timeout) : EXInternal(path) {
  setTimeouts(timeout);
  client_ = std::make_shared<_Client>(server->protocol_);
  (void)server->transport_->open();
}

EXManagerClient::EXManagerClient(const std::string& manager_path,
                                 size_t timeout)
    : EXInternal(manager_path) {
  setTimeouts(timeout);
  client_ = std::make_shared<_ManagerClient>(server->protocol_);
  (void)server->transport_->open();
}

const std::shared_ptr<_Client>& EXClient::get() const {
  return client_;
}

const std::shared_ptr<_ManagerClient>& EXManagerClient::get() const {
  return client_;
}
} // namespace osquery