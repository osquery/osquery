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

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#ifdef OSQUERY_THRIFT
#include "Extension.h"
#include "ExtensionManager.h"
#else
#error "Required -DOSQUERY_THRIFT=/path/to/thrift/gen-cpp"
#endif

namespace osquery {

DECLARE_string(extensions_socket);

/**
 * @brief Helper struct for managing extenion metadata.
 *
 * This structure should match the members of Thrift's InternalExtensionInfo.
 */
struct ExtensionInfo {
  std::string name;
  std::string version;
  std::string sdk_version;

  ExtensionInfo& operator=(const extensions::InternalExtensionInfo& iei) {
    name = iei.name;
    version = iei.version;
    sdk_version = iei.sdk_version;
    return *this;
  }

  ExtensionInfo() {}
  ExtensionInfo(const std::string& name) : name(name) {
    version = OSQUERY_VERSION;
    sdk_version = OSQUERY_VERSION;
  }
};

typedef std::map<RouteUUID, ExtensionInfo> ExtensionList;

inline std::string getExtensionSocket(
    RouteUUID uuid, const std::string& path = FLAGS_extensions_socket) {
  if (uuid == 0) {
    return path;
  } else {
    return path + "." + std::to_string(uuid);
  }
}

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
  ExtensionHandler() {}

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
  void extensions(InternalExtensionList& _return) { _return = extensions_; }

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

 private:
  /// Check if an extension exists by the name it registered.
  bool exists(const std::string& name);

  /// Maintain a map of extension UUID to metadata for tracking deregistrations.
  InternalExtensionList extensions_;
};
}

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class ExtensionWatcher : public InternalRunnable {
 public:
  virtual ~ExtensionWatcher() {}
  ExtensionWatcher(const std::string& manager_path,
                   size_t interval,
                   bool fatal) {
    manager_path_ = manager_path;
    interval_ = interval;
    fatal_ = fatal;
  }

 public:
  /// The Dispatcher thread entry point.
  void enter();

 private:
  /// Exit the extension process with a fatal if the ExtensionManager dies.
  void exitFatal();

 private:
  /// The UNIX domain socket path for the ExtensionManager.
  std::string manager_path_;
  /// The internal in milliseconds to ping the ExtensionManager.
  size_t interval_;
  /// If the ExtensionManager socket is closed, should the extension exit.
  bool fatal_;
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
  ExtensionManagerRunner(const std::string& manager_path) {
    path_ = manager_path;
  }

 public:
  void enter();

 private:
  std::string path_;
};

/// Status get a list of active extenions.
Status getExtensions(ExtensionList& extensions);

/// Internal getExtensions using a UNIX domain socket path.
Status getExtensions(const std::string& manager_path,
                     ExtensionList& extensions);

/// Ping an extension manager or extension.
Status pingExtension(const std::string& path);

/**
 * @brief Call a Plugin exposed by an Extension Registry route.
 *
 * This is mostly a Registry%-internal method used to call an ExtensionHandler
 * call API if a Plugin is requested and had matched an Extension route.
 *
 * @param uuid Route UUID of the matched Extension
 * @param registry The string name for the registry.
 * @param item A string identifier for this registry item.
 * @param request The plugin request input.
 * @param response The plugin response output.
 * @return Success indicates Extension API call success and Extension's
 * Registry::call success.
 */
Status callExtension(const RouteUUID uuid,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response);

/// Internal callExtension implementation using a UNIX domain socket path.
Status callExtension(const std::string& extension_path,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response);

/// The main runloop entered by an Extension, start an ExtensionRunner thread.
Status startExtension();

/// Internal startExtension implementation using a UNIX domain socket path.
Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& sdk_version);

/// Start an ExtensionWatcher thread.
Status startExtensionWatcher(const std::string& manager_path,
                             size_t interval,
                             bool fatal);

/// Start an ExtensionManagerRunner thread.
Status startExtensionManager();

/// Internal startExtensionManager implementation.
Status startExtensionManager(const std::string& manager_path);
}
