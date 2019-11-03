/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/dispatcher.h>
#include <osquery/extensions.h>
#include <osquery/utils/mutex.h>

#include <memory>
#include <string>

namespace osquery {

struct ImplExtensionRunner;

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
} // namespace osquery
