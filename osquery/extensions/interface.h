/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/extensions.h>

#include "osquery/dispatcher/dispatcher.h"

// osquery is built with various versions of thrift that use different search
// paths for their includes. Unfortunately, changing include paths is not
// possible in every build system.
// clang-format off
#include CONCAT(OSQUERY_THRIFT_SERVER_LIB,/TThreadPoolServer.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/protocol/TBinaryProtocol.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/transport/TServerSocket.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/transport/TBufferTransports.h)
#include CONCAT(OSQUERY_THRIFT_LIB,/transport/TSocket.h)

// Include intermediate Thrift-generated interface definitions.
#include CONCAT(OSQUERY_THRIFT,Extension.h)
#include CONCAT(OSQUERY_THRIFT,ExtensionManager.h)
// clang-format on

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;
using namespace apache::thrift::concurrency;

namespace osquery {
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
  void ping(ExtensionStatus& _return);

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
            const ExtensionPluginRequest& request);

 protected:
  RouteUUID uuid_;
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
  ExtensionManagerHandler() {}

  /// Return a list of Route UUIDs and extension metadata.
  void extensions(InternalExtensionList& _return);

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
  void options(InternalOptionList& _return);

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
                         const ExtensionRegistry& registry);

  /**
   * @brief Request an Extension removal and removal of Registry routes.
   *
   * When an Extension process is gracefull killed it should deregister.
   * Other priviledged tools may choose to deregister an Extension by
   * the transient Extension's Route UUID, obtained using
   * ExtensionManagerHandler::extensions.
   *
   * @param _return The output Status.
   * @param uuid The assigned Route UUID to deregister.
   */
  void deregisterExtension(ExtensionStatus& _return,
                           const ExtensionRouteUUID uuid);

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
  void query(ExtensionResponse& _return, const std::string& sql);

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
  void getQueryColumns(ExtensionResponse& _return, const std::string& sql);

 private:
  /// Check if an extension exists by the name it registered.
  bool exists(const std::string& name);
  /// Introspect into the registry, checking if any extension routes have been
  /// removed.
  void refresh();

  /// Maintain a map of extension UUID to metadata for tracking deregistrations.
  InternalExtensionList extensions_;
};
}

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class ExtensionWatcher : public InternalRunnable {
 public:
  virtual ~ExtensionWatcher() {}
  ExtensionWatcher(const std::string& path, size_t interval, bool fatal)
      : path_(path), interval_(interval), fatal_(fatal) {
    interval_ = (interval_ < 200) ? 200 : interval_;
  }

 public:
  /// The Dispatcher thread entry point.
  void enter();
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

  void watch();
};

/// A Dispatcher service thread that starts ExtensionHandler.
class ExtensionRunner : public InternalRunnable {
 public:
  virtual ~ExtensionRunner();
  ExtensionRunner(const std::string& manager_path, RouteUUID uuid) {
    path_ = getExtensionSocket(uuid, manager_path);
    uuid_ = uuid;
  }

 public:
  /// The Dispatcher thread entry point.
  void enter();

  /// Access the UUID provided by the ExtensionManager.
  RouteUUID getUUID() { return uuid_; }

 private:
  /// The UNIX domain socket used for requests from the ExtensionManager.
  std::string path_;
  /// The unique and transient Extension UUID assigned by the ExtensionManager.
  RouteUUID uuid_;
};

/// A Dispatcher service thread that starts ExtensionManagerHandler.
class ExtensionManagerRunner : public InternalRunnable {
 public:
  virtual ~ExtensionManagerRunner();
  explicit ExtensionManagerRunner(const std::string& manager_path) {
    path_ = manager_path;
  }

 public:
  void enter();

 private:
  std::string path_;
};

/// Internal accessor for extension clients.
class EXInternal {
 public:
  explicit EXInternal(const std::string& path)
      : socket_(new TSocket(path)),
        transport_(new TBufferedTransport(socket_)),
        protocol_(new TBinaryProtocol(transport_)) {}

  virtual ~EXInternal() { transport_->close(); }

 protected:
  OSQUERY_THRIFT_POINTER::shared_ptr<TSocket> socket_;
  OSQUERY_THRIFT_POINTER::shared_ptr<TTransport> transport_;
  OSQUERY_THRIFT_POINTER::shared_ptr<TProtocol> protocol_;
};

/// Internal accessor for a client to an extension (from an extension manager).
class EXClient : public EXInternal {
 public:
  explicit EXClient(const std::string& path) : EXInternal(path) {
    client_ = std::make_shared<extensions::ExtensionClient>(protocol_);
    transport_->open();
  }

  const std::shared_ptr<extensions::ExtensionClient>& get() { return client_; }

 private:
  std::shared_ptr<extensions::ExtensionClient> client_;
};

/// Internal accessor for a client to an extension manager (from an extension).
class EXManagerClient : public EXInternal {
 public:
  explicit EXManagerClient(const std::string& manager_path)
      : EXInternal(manager_path) {
    client_ = std::make_shared<extensions::ExtensionManagerClient>(protocol_);
    transport_->open();
  }

  const std::shared_ptr<extensions::ExtensionManagerClient>& get() {
    return client_;
  }

 private:
  std::shared_ptr<extensions::ExtensionManagerClient> client_;
};
}
