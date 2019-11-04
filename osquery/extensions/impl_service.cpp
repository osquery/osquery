/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/extensions/handler.h>
#include <osquery/extensions/interface.h>
#include <osquery/extensions/service.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>

#include <thrift/concurrency/ThreadManager.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TBufferTransports.h>

#ifdef WIN32
#include <thrift/transport/TPipeServer.h>
#else
#include <thrift/transport/TServerSocket.h>
#endif

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/lock_types.hpp>
#include <boost/thread/locks.hpp>

using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::server;
using namespace apache::thrift::transport;

namespace osquery {

#ifdef WIN32
using TPlatformServerSocket = TPipeServer;
#else
using TPlatformServerSocket = TServerSocket;
#endif

class ThriftServerEventHandler : public TServerEventHandler,
                                 boost::noncopyable {
 public:
  ThriftServerEventHandler() : server_is_listening_{false} {}

  void preServe() override {
    boost::unique_lock<boost::mutex> lock(m_);
    server_is_listening_ = true;
    server_is_listening_cv_.notify_all();
  }

  /**
    Waits either until the preServe() function is called,
    so until the TServerSocket has exited from its listen(),
    or a one minute timeout is reached.
    The one minute timeout is there only to mitigate a possible developer error.
  */
  void waitUntilServerIsListening() {
    boost::unique_lock<boost::mutex> lock(m_);
    if (!server_is_listening_cv_.wait_for(
            lock, boost::chrono::minutes(1), [this] {
              return server_is_listening_;
            })) {
      VLOG(1)
          << "Wait for Thrift server listen() has timed out. A tentative of "
             "stopping a server that will never start has been attempted";
    }
  }

  void reset() {
    boost::unique_lock<boost::mutex> lock(m_);
    server_is_listening_ = false;
  }

 private:
  boost::condition_variable server_is_listening_cv_;
  boost::mutex m_;
  bool server_is_listening_;
};

struct ImplExtensionRunner {
  std::shared_ptr<TServerTransport> transport;
  std::shared_ptr<TThreadedServer> server;
  std::shared_ptr<TProcessor> processor;
  std::shared_ptr<ThriftServerEventHandler> server_event_handler;
};

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

  server_->server_event_handler = std::make_shared<ThriftServerEventHandler>();
  server_->server->setServerEventHandler(server_->server_event_handler);
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
    server_->server_event_handler->waitUntilServerIsListening();
    server_->server_event_handler->reset();
    server_->server->stop();
  }
}

void ExtensionRunnerInterface::stopServerManager() {
  if (server_->server != nullptr) {
    removeStalePaths(path_);
  }
}

} // namespace osquery
