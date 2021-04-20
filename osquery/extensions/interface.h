/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/query.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/extensions/extensions.h>

namespace osquery {

/**
 * An option is a 'basic' flag, the only important information is value.
 */
struct Option {
  /// Current flag value.
  std::string value;
  /// Initial flag value.
  std::string default_value;
  /// String representation of type (unused).
  std::string type;
};

/// This is replicated from the Thrift IDL.
enum class ExtensionCode {
  EXT_SUCCESS = 0,
  EXT_FAILED = 1,
  EXT_FATAL = 2,
};

using OptionList = std::map<std::string, Option>;
using ExtensionRouteTable = std::map<std::string, PluginResponse>;
using ExtensionRegistry = std::map<std::string, ExtensionRouteTable>;

/**
 * @brief The basic API functions that our Thrift server and client implements.
 *
 * We include this abstract to force the server (interface) and clients to
 * include the required APIs.
 *
 * For each interface, a child must implement the actual Thrift endpoints and
 * call the methods included here, which contain the logic. This is a little
 * bit of overhead that was already a sunk cost for osquery-- meaning we
 * were already translating Thrift structures to library structures.
 */
class ExtensionAPI {
 public:
  virtual ~ExtensionAPI() = default;

 public:
  virtual Status ping() = 0;
  virtual Status call(const std::string& registry,
                      const std::string& item,
                      const PluginRequest& request,
                      PluginResponse& response) = 0;
  virtual void shutdown() = 0;
};

class ExtensionManagerAPI {
 public:
  virtual ~ExtensionManagerAPI() = default;

 public:
  virtual ExtensionList extensions() = 0;
  virtual OptionList options() = 0;
  virtual Status registerExtension(const ExtensionInfo& info,
                                   const ExtensionRegistry& registry,
                                   RouteUUID& uuid) = 0;
  virtual Status deregisterExtension(RouteUUID uuid) = 0;
  virtual Status query(const std::string& sql, QueryData& qd) = 0;
  virtual Status getQueryColumns(const std::string& sql, QueryData& qd) = 0;
};

/**
 * @brief The Thrift API server used by an osquery Extension process.
 *
 * An extension will load and start a thread to serve the ExtensionHandler
 * Thrift runloop. This handler is the implementation of the thrift IDL spec.
 * It implements all the Extension API handlers.
 *
 */
class ExtensionInterface : public ExtensionAPI {
 public:
  ExtensionInterface() : ExtensionInterface(0) {}
  explicit ExtensionInterface(RouteUUID uuid) : uuid_(uuid) {}

 public:
  virtual Status ping() override;
  virtual Status call(const std::string& registry,
                      const std::string& item,
                      const PluginRequest& request,
                      PluginResponse& response) override;
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
class ExtensionManagerInterface : public ExtensionInterface,
                                  public ExtensionManagerAPI {
 public:
  /// Return a list of Route UUIDs and extension metadata.
  virtual ExtensionList extensions() override;

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
  virtual OptionList options() override;

  /**
   * @brief Request a Route UUID and advertise a set of Registry routes.
   *
   * When an Extension starts it must call registerExtension using a well known
   * ExtensionManager UNIX domain socket path. The ExtensionManager will check
   * the broadcasted routes for duplicates as well as enforce SDK version
   * compatibility checks. On success the Extension is returned a Route UUID and
   * begins to serve the ExtensionHandler Thrift API.
   *
   * @return The output Status and optional assigned RouteUUID.
   * @param info The osquery Thrift-internal Extension metadata container.
   * @param registry The Extension's Registry::getBroadcast information.
   */
  virtual Status registerExtension(const ExtensionInfo& info,
                                   const ExtensionRegistry& registry,
                                   RouteUUID& uuid) override;

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
  virtual Status deregisterExtension(RouteUUID uuid) override;

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
  virtual Status query(const std::string& sql, QueryData& qd) override;

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
  virtual Status getQueryColumns(const std::string& sql,
                                 QueryData& qd) override;

 private:
  /// Check if an extension exists by the name it registered.
  bool exists(const std::string& name);

  /// Introspect into the registry, checking if any extension routes have been
  /// removed.
  void refresh();

  /// Maintain a map of extension UUID to metadata for tracking deregistration.
  ExtensionList extensions_;

  /// Mutex for extensions accessors.
  Mutex extensions_mutex_;
};

struct ImplExtensionRunner;
struct ImplExtensionClient;

/**
 * This implements a small API around setting up and running Thrift
 * Servers. The implementation details and members are private and stored in
 * the PIMPL structures defined above.
 *
 * An implementation will exist for Apache Thrift and for FBThrift.
 */
class ExtensionRunnerInterface {
 public:
  virtual ~ExtensionRunnerInterface();
  ExtensionRunnerInterface();

  /**
   * Call into the Thrift server's server implementation.
   */
  void serve();

  /// Set up structures.
  void connect();

  /// Create handler/processor.
  void init(RouteUUID uuid, bool manager = false);

  /// Stop server.
  void stopServer();

  /// Stop server manager.
  void stopServerManager();

 protected:
  /// The UNIX domain socket used for requests from the ExtensionManager.
  std::string path_;

  /// True if the extension is an extension manager.
  bool manager_;

  /// Thrift server implementation.
  std::unique_ptr<ImplExtensionRunner> server_;
};

class ExtensionRunnerCore : public InternalRunnable,
                            public ExtensionRunnerInterface {
 public:
  virtual ~ExtensionRunnerCore();
  explicit ExtensionRunnerCore(const std::string& path);

 public:
  /// Given a handler transport and protocol start a thrift threaded server.
  void startServer();

  // The Dispatcher thread service stop point.
  void stop() override;

 protected:
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
  explicit ExtensionManagerRunner(const std::string& manager_path);

 public:
  void start() override;
};

/// Internal accessor for extension clients.
class ExtensionClientCore : private boost::noncopyable {
 public:
  virtual ~ExtensionClientCore();

 public:
  /**
   * @brief Initialize the UNIX socket from a string pathname.
   *
   * A very basic client can just store the string.
   * More complex clients can create the client structure.
   */
  void init(const std::string& path, bool manager = false);

  /// Set the receive and send timeout in seconds.
  void setTimeouts(size_t timeout);

  /// Check if the client is an extension manager.
  bool manager();

 protected:
  /// Path to extension server socket.
  std::string path_;

  /// True if the client is an extension manager client.
  bool manager_;

  /// Thrift client implementation.
  std::unique_ptr<ImplExtensionClient> client_;
};

/// Internal accessor for a client to an extension (from an extension manager).
class ExtensionClient : public ExtensionClientCore, public ExtensionAPI {
 public:
  /**
   * @brief Create a client to a client extension.
   *
   * @note The default timeout to wait for buffered (whole-content) responses
   * is 5 minutes.
   * @param path This is the socket path for the client communication.
   * @param timeout [optional] time in seconds to wait for input.
   */
  explicit ExtensionClient(const std::string& path, size_t timeout = 0);
  ~ExtensionClient();

 protected:
  ExtensionClient() = default;

 public:
  /// Ping a server and have it fill in the extension's UUID as the code.
  Status ping() override;

  /// Call an extension's plugin.
  Status call(const std::string& registry,
              const std::string& item,
              const PluginRequest& request,
              PluginResponse& response) override;

  /// Request that the extension stop.
  void shutdown() override;
};

/// Internal accessor for a client to an extension manager (from an extension).
class ExtensionManagerClient : public ExtensionClient,
                               public ExtensionManagerAPI {
 public:
  /**
   * @brief Create a client to a manager extension.
   *
   * @param path This is the socket path for the manager communication.
   * @param timeout [optional] time in seconds to wait for input.
   */
  explicit ExtensionManagerClient(const std::string& path, size_t timeout = 0);
  ~ExtensionManagerClient();

 public:
  /// List all osquery extensions.
  ExtensionList extensions() override;

  /// List all osquery options (gflags).
  OptionList options() override;

  /// Regiester yourself as a new extension.
  Status registerExtension(const ExtensionInfo& info,
                           const ExtensionRegistry& registry,
                           RouteUUID& uuid) override;

  /// Remove an extension.
  Status deregisterExtension(RouteUUID uuid) override;

  /// Issue a query.
  Status query(const std::string& sql, QueryData& qd) override;

  /// Get column information from a query.
  Status getQueryColumns(const std::string& sql, QueryData& qd) override;
};

/// Attempt to remove all stale extension sockets.
void removeStalePaths(const std::string& manager);
} // namespace osquery
