/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/dispatcher.h>
#include <osquery/extensions.h>

#ifdef WIN32
#pragma warning(push, 3)

/*
 * MSVC complains that ExtensionManagerHandler inherits the call() function from
 * ExtensionHandler via dominance. This is because ExtensionManagerHandler
 * implements ExtensionManagerIf and ExtensionHandler who both implement
 * ExtensionIf. ExtensionIf declares a virtual call() function that
 * ExtensionHandler defines. This _shouldn't_ cause any issues.
 */
#pragma warning(disable : 4250)
#endif

#include <thrift/server/TThreadedServer.h>
#include <thrift/protocol/TBinaryProtocol.h>

#ifdef WIN32
#include <thrift/transport/TPipeServer.h>
#include <thrift/transport/TPipe.h>
#else
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TSocket.h>
#endif

#include <thrift/transport/TBufferTransports.h>
#include <thrift/concurrency/ThreadManager.h>

// Include intermediate Thrift-generated interface definitions.
#include "Extension.h"
#include "ExtensionManager.h"

namespace osquery {

using namespace apache::thrift;
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

typedef std::shared_ptr<TProcessor> TProcessorRef;
typedef std::shared_ptr<TServerTransport> TServerTransportRef;
typedef std::shared_ptr<TTransportFactory> TTransportFactoryRef;
typedef std::shared_ptr<TProtocolFactory> TProtocolFactoryRef;
typedef std::shared_ptr<ThreadManager> TThreadManagerRef;

using TThreadedServerRef = std::shared_ptr<TThreadedServer>;

namespace extensions {

/**
 * @brief The Thrift API server used by an osquery Extension process.
 *
 * An extension will load and start a thread to serve the ExtensionHandler
 * Thrift runloop. This handler is the implementation of the thrift IDL spec.
 * It implements all the Extension API handlers.
 *
 */
class ExtensionHandler : virtual public ExtensionIf {
 public:
  ExtensionHandler() : uuid_(0) {}
  explicit ExtensionHandler(RouteUUID uuid) : uuid_(uuid) {}

  /// Ping an Extension for status and metrics.
  void ping(ExtensionStatus& _return) override;

  /**
   * @brief The Thrift API used by Registry::call for an extension route.
   *
   * @param _return The return response (combo Status and PluginResponse).
   * @param registry The name of the Extension registry.
   * @param item The Extension plugin name.
   * @param request The plugin request.
   */
  void call(ExtensionResponse& _return,
            const std::string& registry,
            const std::string& item,
            const ExtensionPluginRequest& request) override;

  /// Request an extension to shutdown.
  virtual void shutdown() override;

 protected:
  /// Transient UUID assigned to the extension after registering.
  std::atomic<RouteUUID> uuid_;
};

/**
 * @brief The Thrift API server used by an osquery process.
 *
 * An extension will load and start a thread to serve the
 * ExtensionManagerHandler. This listens for extensions and allows them to
 * register their Registry route information. Calls to the registry may then
 * match a route exposed by an extension.
 * This handler is the implementation of the thrift IDL spec.
 * It implements all the ExtensionManager API handlers.
 *
 */
class ExtensionManagerHandler : virtual public ExtensionManagerIf,
                                public ExtensionHandler {
 public:
  ExtensionManagerHandler();

  /// Return a list of Route UUIDs and extension metadata.
  void extensions(InternalExtensionList& _return) override;

  /**
   * @brief Return a map of osquery options (Flags, bootstrap CLI flags).
   *
   * osquery options are set via command line flags or overridden by a config
   * options dictionary. There are some CLI-only flags that should never
   * be overridden. If a bootstrap flag is changed there is undefined behavior
   * since bootstrap candidates are settings needed before a configuration
   * plugin is setUp.
   *
   * Extensions may broadcast config or logger plugins that need a snapshot
   * of the current options. The best example is the `config_plugin` bootstrap
   * flag.
   */
  void options(InternalOptionList& _return) override;

  /**
   * @brief Request a Route UUID and advertise a set of Registry routes.
   *
   * When an Extension starts it must call registerExtension using a well known
   * ExtensionManager UNIX domain socket path. The ExtensionManager will check
   * the broadcasted routes for duplicates as well as enforce SDK version
   * compatibility checks. On success the Extension is returned a Route UUID and
   * begins to serve the ExtensionHandler Thrift API.
   *
   * @param _return The output Status and optional assigned RouteUUID.
   * @param info The osquery Thrift-internal Extension metadata container.
   * @param registry The Extension's Registry::getBroadcast information.
   */
  void registerExtension(ExtensionStatus& _return,
                         const InternalExtensionInfo& info,
                         const ExtensionRegistry& registry) override;

  /**
   * @brief Request an Extension removal and removal of Registry routes.
   *
   * When an Extension process is graceful killed it should deregister.
   * Other privileged tools may choose to deregister an Extension by
   * the transient Extension's Route UUID, obtained using
   * ExtensionManagerHandler::extensions.
   *
   * @param _return The output Status.
   * @param uuid The assigned Route UUID to deregister.
   */
  void deregisterExtension(ExtensionStatus& _return,
                           const ExtensionRouteUUID uuid) override;

  /**
   * @brief Execute an SQL statement in osquery core.
   *
   * Extensions do not have access to the internal SQLite implementation.
   * For complex queries (beyond select all from a table) the statement must
   * be passed into SQLite.
   *
   * @param _return The output Status and QueryData (as response).
   * @param sql The sql statement.
   */
  void query(ExtensionResponse& _return, const std::string& sql) override;

  /**
   * @brief Get SQL column information for SQL statements in osquery core.
   *
   * Extensions do not have access to the internal SQLite implementation.
   * For complex queries (beyond metadata for a table) the statement must
   * be passed into SQLite.
   *
   * @param _return The output Status and TableColumns (as response).
   * @param sql The sql statement.
   */
  void getQueryColumns(ExtensionResponse& _return,
                       const std::string& sql) override;

 protected:
  /// A shutdown request does not apply to ExtensionManagers.
  void shutdown() override {}

 private:
  /// Check if an extension exists by the name it registered.
  bool exists(const std::string& name);

  /// Introspect into the registry, checking if any extension routes have been
  /// removed.
  void refresh();

  /// Maintain a map of extension UUID to metadata for tracking deregistration.
  InternalExtensionList extensions_;

  /// Mutex for extensions accessors.
  Mutex extensions_mutex_;
};

typedef std::shared_ptr<ExtensionHandler> ExtensionHandlerRef;
typedef std::shared_ptr<ExtensionManagerHandler> ExtensionManagerHandlerRef;
}

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class ExtensionWatcher : public InternalRunnable {
 public:
  virtual ~ExtensionWatcher() = default;
  ExtensionWatcher(const std::string& path, size_t interval, bool fatal);

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// Perform health checks.
  virtual void watch();

 protected:
  /// Exit the extension process with a fatal if the ExtensionManager dies.
  void exitFatal(int return_code = 1);

 protected:
  /// The UNIX domain socket path for the ExtensionManager.
  std::string path_;

  /// The internal in milliseconds to ping the ExtensionManager.
  size_t interval_;

  /// If the ExtensionManager socket is closed, should the extension exit.
  bool fatal_;
};

class ExtensionManagerWatcher : public ExtensionWatcher {
 public:
  ExtensionManagerWatcher(const std::string& path, size_t interval)
      : ExtensionWatcher(path, interval, false) {}

  /// The Dispatcher thread entry point.
  void start() override;

  /// Start a specialized health check for an ExtensionManager.
  void watch() override;

 private:
  /// Allow extensions to fail for several intervals.
  std::map<RouteUUID, size_t> failures_;
};

class ExtensionRunnerCore : public InternalRunnable {
 public:
  virtual ~ExtensionRunnerCore();
  explicit ExtensionRunnerCore(const std::string& path)
      : InternalRunnable("ExtensionRunnerCore"),
        path_(path),
        server_(nullptr) {}

 public:
  /// Given a handler transport and protocol start a thrift threaded server.
  void startServer(TProcessorRef processor);

  // The Dispatcher thread service stop point.
  void stop() override;

 protected:
  /// The UNIX domain socket used for requests from the ExtensionManager.
  std::string path_;

  /// Transport instance, will be interrupted if the thread is removed.
  TServerTransportRef transport_{nullptr};

  /// Server instance, will be stopped if thread service is removed.
  TThreadedServerRef server_{nullptr};

  /// Protect the service start and stop, this mutex protects server creation.
  Mutex service_start_;

  /// Record a dispatcher's request to stop the service.
  bool service_stopping_{false};
};

/**
 * @brief A Dispatcher service thread that starts ExtensionHandler.
 *
 * This runner will start a Thrift Extension server, call serve, and wait
 * until the extension exists or the ExtensionManager (core) terminates or
 * deregisters the extension.
 *
 */
class ExtensionRunner : public ExtensionRunnerCore {
 public:
  ExtensionRunner(const std::string& manager_path, RouteUUID uuid);

 public:
  void start() override;

  /// Access the UUID provided by the ExtensionManager.
  RouteUUID getUUID() const;

 private:
  /// The unique and transient Extension UUID assigned by the ExtensionManager.
  RouteUUID uuid_;
};

/**
 * @brief A Dispatcher service thread that starts ExtensionManagerHandler.
 *
 * This runner will start a Thrift ExtensionManager server, call serve, and wait
 * until for extensions to register, or thrift API calls.
 *
 */
class ExtensionManagerRunner : public ExtensionRunnerCore {
 public:
  virtual ~ExtensionManagerRunner();
  explicit ExtensionManagerRunner(const std::string& manager_path)
      : ExtensionRunnerCore(manager_path) {}

 public:
  void start() override;
};

/// Internal accessor for extension clients.
class EXInternal : private boost::noncopyable {
 public:
  explicit EXInternal(const std::string& path)
      : socket_(new TPlatformSocket(path)),
        transport_(new TBufferedTransport(socket_)),
        protocol_(new TBinaryProtocol(transport_)) {}

  // Set the receive and send timeout.
  void setTimeouts(size_t timeout);

  virtual ~EXInternal();

 protected:
  TPlatformSocketRef socket_;
  TTransportRef transport_;
  TProtocolRef protocol_;
};

/// Internal accessor for a client to an extension (from an extension manager).
class EXClient : public EXInternal {
 public:
  /**
   * @brief Create a client to a client extension.
   *
   * @note The default timeout to wait for buffered (whole-content) responses
   * is 5 minutes.
   * @param path This is the socket path for the client communication.
   * @param timeout [optional] time in milliseconds to wait for input.
   */
  explicit EXClient(const std::string& path, size_t timeout = 5000 * 60);

  const std::shared_ptr<extensions::ExtensionClient>& get() const;

 private:
  std::shared_ptr<extensions::ExtensionClient> client_;
};

/// Internal accessor for a client to an extension manager (from an extension).
class EXManagerClient : public EXInternal {
 public:
  /**
   * @brief Create a client to a manager extension.
   *
   * @param path This is the socket path for the manager communication.
   * @param timeout [optional] time in milliseconds to wait for input.
   */
  explicit EXManagerClient(const std::string& manager_path,
                           size_t timeout = 5000 * 60);

  const std::shared_ptr<extensions::ExtensionManagerClient>& get() const;

 private:
  std::shared_ptr<extensions::ExtensionManagerClient> client_;
};
}

#ifdef WIN32
#pragma warning(pop)
#endif
