/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <csignal>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/events.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/extensions/interface.h"
#include "osquery/core/watcher.h"

using namespace osquery::extensions;

namespace fs = boost::filesystem;

namespace osquery {

// Millisecond latency between initalizing manager pings.
const size_t kExtensionInitializeLatencyUS = 20000;

#ifdef __APPLE__
const std::string kModuleExtension = ".dylib";
#else
const std::string kModuleExtension = ".so";
#endif

CLI_FLAG(bool, disable_extensions, false, "Disable extension API");

CLI_FLAG(string,
         extensions_socket,
         "/var/osquery/osquery.em",
         "Path to the extensions UNIX domain socket")

CLI_FLAG(string,
         extensions_autoload,
         "/etc/osquery/extensions.load",
         "Optional path to a list of autoloaded & managed extensions")

CLI_FLAG(string,
         extensions_timeout,
         "3",
         "Seconds to wait for autoloaded extensions");

CLI_FLAG(string,
         extensions_interval,
         "3",
         "Seconds delay between connectivity checks")

CLI_FLAG(string,
         modules_autoload,
         "/etc/osquery/modules.load",
         "Optional path to a list of autoloaded registry modules")

/**
 * @brief Alias the extensions_socket (used by core) to a simple 'socket'.
 *
 * Extension binaries will more commonly set the path to an extension manager
 * socket. Alias the long switch name to 'socket' for an easier UX.
 *
 * We include timeout and interval, where the 'extensions_' prefix is removed
 * in the alias since we are already within the context of an extension.
 */
EXTENSION_FLAG_ALIAS(socket, extensions_socket);
EXTENSION_FLAG_ALIAS(timeout, extensions_timeout);
EXTENSION_FLAG_ALIAS(interval, extensions_interval);

void ExtensionWatcher::start() {
  // Watch the manager, if the socket is removed then the extension will die.
  while (true) {
    watch();
    interruptableSleep(interval_);
  }
}

void ExtensionWatcher::exitFatal(int return_code) {
  // Exit the extension.
  ::exit(return_code);
}

void ExtensionWatcher::watch() {
  ExtensionStatus status;
  try {
    auto client = EXManagerClient(path_);
    // Ping the extension manager until it goes down.
    client.get()->ping(status);
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extension watcher ending: osquery core has gone away";
    exitFatal(0);
  }

  if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
    exitFatal();
  }
}

void ExtensionManagerWatcher::watch() {
  // Watch the set of extensions, if the socket is removed then the extension
  // will be deregistered.
  const auto uuids = Registry::routeUUIDs();

  ExtensionStatus status;
  for (const auto& uuid : uuids) {
    try {
      auto client = EXClient(getExtensionSocket(uuid));

      // Ping the extension until it goes down.
      client.get()->ping(status);
    } catch (const std::exception& e) {
      LOG(INFO) << "Extension UUID " << uuid << " has gone away";
      Registry::removeBroadcast(uuid);
      continue;
    }

    if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
      Registry::removeBroadcast(uuid);
    }
  }
}

inline Status socketWritable(const fs::path& path) {
  if (pathExists(path).ok()) {
    if (!isWritable(path).ok()) {
      return Status(1, "Cannot write extension socket: " + path.string());
    }

    if (!remove(path).ok()) {
      return Status(1, "Cannot remove extension socket: " + path.string());
    }
  } else {
    if (!pathExists(path.parent_path()).ok()) {
      return Status(1, "Extension socket directory missing: " + path.string());
    }

    if (!isWritable(path.parent_path()).ok()) {
      return Status(1, "Cannot write extension socket: " + path.string());
    }
  }
  return Status(0, "OK");
}

void loadExtensions() {
  // Disabling extensions will disable autoloading.
  if (FLAGS_disable_extensions) {
    return;
  }

  // Optionally autoload extensions
  auto status = loadExtensions(FLAGS_extensions_autoload);
  if (!status.ok()) {
    VLOG(1) << "Could not autoload extensions: " << status.what();
  }
}

void loadModules() {
  auto status = loadModules(FLAGS_modules_autoload);
  if (!status.ok()) {
    VLOG(1) << "Could not autoload modules: " << status.what();
  }
}

Status loadExtensions(const std::string& loadfile) {
  std::string autoload_paths;
  if (readFile(loadfile, autoload_paths).ok()) {
    for (auto& path : osquery::split(autoload_paths, "\n")) {
      boost::trim(path);
      if (path.size() > 0 && path[0] != '#' && path[0] != ';') {
        Watcher::addExtensionPath(path);
      }
    }
    return Status(0, "OK");
  }
  return Status(1, "Failed reading: " + loadfile);
}

Status loadModuleFile(const std::string& path) {
  fs::path module(path);
  if (safePermissions(module.parent_path().string(), path)) {
    if (module.extension().string() == kModuleExtension) {
      // Silently allow module load failures to drop.
      RegistryModuleLoader loader(module.string());
      loader.init();
      return Status(0, "OK");
    }
  }
  return Status(1, "Module check failed");
}

Status loadModules(const std::string& loadfile) {
  // Split the search path for modules using a ':' delimiter.
  std::string autoload_paths;
  if (readFile(loadfile, autoload_paths).ok()) {
    auto status = Status(0, "OK");
    for (auto& module_path : osquery::split(autoload_paths, "\n")) {
      boost::trim(module_path);
      auto path_status = loadModuleFile(module_path);
      if (!path_status.ok()) {
        status = path_status;
      }
    }
    // Return an aggregate failure if any load fails (invalid search path).
    return status;
  }
  return Status(1, "Failed reading: " + loadfile);
}

Status extensionPathActive(const std::string& path, bool use_timeout = false) {
  // Make sure the extension manager path exists, and is writable.
  size_t delay = 0;
  // The timeout is given in seconds, but checked interval is microseconds.
  size_t timeout = atoi(FLAGS_extensions_timeout.c_str()) * 1000000;
  if (timeout < kExtensionInitializeLatencyUS * 10) {
    timeout = kExtensionInitializeLatencyUS * 10;
  }
  do {
    if (pathExists(path) && isWritable(path)) {
      try {
        auto client = EXManagerClient(path);
        return Status(0, "OK");
      } catch (const std::exception& e) {
        // Path might exist without a connected extension or extension manager.
      }
    }
    // Only check active once if this check does not allow a timeout.
    if (!use_timeout || timeout == 0) {
      break;
    }
    // Increase the total wait detail.
    delay += kExtensionInitializeLatencyUS;
    ::usleep(kExtensionInitializeLatencyUS);
  } while (delay < timeout);
  return Status(1, "Extension socket not available: " + path);
}

Status startExtension(const std::string& name, const std::string& version) {
  return startExtension(name, version, "0.0.0");
}

Status startExtension(const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version) {
  Registry::setExternal();
  // Latency converted to milliseconds, used as a thread interruptible.
  auto latency = atoi(FLAGS_extensions_interval.c_str()) * 1000;
  auto status = startExtensionWatcher(FLAGS_extensions_socket, latency, true);
  if (!status.ok()) {
    // If the threaded watcher fails to start, fail the extension.
    return status;
  }

  status = startExtension(
      FLAGS_extensions_socket, name, version, min_sdk_version, kSDKVersion);
  if (!status.ok()) {
    // If the extension failed to start then the EM is most likely unavailable.
    return status;
  }

  try {
    // The extension does nothing but serve the thrift API.
    // Join on both the thrift and extension manager watcher services.
    Dispatcher::joinServices();
  } catch (const std::exception& e) {
    // The extension manager may shutdown without notifying the extension.
    return Status(0, e.what());
  }

  // An extension will only return on failure.
  return Status(0, "Extension was shutdown");
}

Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version,
                      const std::string& sdk_version) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // The Registry broadcast is used as the ExtensionRegistry.
  auto broadcast = Registry::getBroadcast();
  // The extension will register and provide name, version, sdk details.
  InternalExtensionInfo info;
  info.name = name;
  info.version = version;
  info.sdk_version = sdk_version;
  info.min_sdk_version = min_sdk_version;

  // If registration is successful, we will also request the manager's options.
  InternalOptionList options;
  // Register the extension's registry broadcast with the manager.
  ExtensionStatus ext_status;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->registerExtension(ext_status, info, broadcast);
    // The main reason for a failed registry is a duplicate extension name
    // (the extension process is already running), or the extension broadcasts
    // a duplicate registry item.
    if (ext_status.code != ExtensionCode::EXT_SUCCESS) {
      return Status(ext_status.code, ext_status.message);
    }
    // Request the core options, mainly to set the active registry plugins for
    // logger and config.
    client.get()->options(options);
  } catch (const std::exception& e) {
    return Status(1, "Extension register failed: " + std::string(e.what()));
  }

  // Now that the uuid is known, try to clean up stale socket paths.
  auto extension_path = getExtensionSocket(ext_status.uuid, manager_path);
  status = socketWritable(extension_path);
  if (!status) {
    return status;
  }

  // Set the active config and logger plugins. The core will arbitrate if the
  // plugins are not available in the extension's local registry.
  Registry::setActive("config", options["config_plugin"].value);
  Registry::setActive("logger", options["logger_plugin"].value);
  // Set up all lazy registry plugins and the active config/logger plugin.
  Registry::setUp();

  // Start the extension's Thrift server
  Dispatcher::addService(
      std::make_shared<ExtensionRunner>(manager_path, ext_status.uuid));
  VLOG(1) << "Extension (" << name << ", " << ext_status.uuid << ", " << version
          << ", " << sdk_version << ") registered";
  return Status(0, std::to_string(ext_status.uuid));
}

Status queryExternal(const std::string& manager_path,
                     const std::string& query,
                     QueryData& results) {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(manager_path);
  if (!status.ok()) {
    return status;
  }

  ExtensionResponse response;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->query(response, query);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  for (const auto& row : response.response) {
    results.push_back(row);
  }

  return Status(response.status.code, response.status.message);
}

Status queryExternal(const std::string& query, QueryData& results) {
  return queryExternal(FLAGS_extensions_socket, query, results);
}

Status getQueryColumnsExternal(const std::string& manager_path,
                               const std::string& query,
                               TableColumns& columns) {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(manager_path);
  if (!status.ok()) {
    return status;
  }

  ExtensionResponse response;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->getQueryColumns(response, query);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Translate response map: {string: string} to a vector: pair(name, type).
  for (const auto& column : response.response) {
    for (const auto& column_detail : column) {
      columns.push_back(make_pair(column_detail.first, column_detail.second));
    }
  }

  return Status(response.status.code, response.status.message);
}

Status getQueryColumnsExternal(const std::string& query,
                               TableColumns& columns) {
  return getQueryColumnsExternal(FLAGS_extensions_socket, query, columns);
}

Status pingExtension(const std::string& path) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }

  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(path);
  if (!status.ok()) {
    return status;
  }

  ExtensionStatus ext_status;
  try {
    auto client = EXClient(path);
    client.get()->ping(ext_status);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return Status(ext_status.code, ext_status.message);
}

Status getExtensions(ExtensionList& extensions) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return getExtensions(FLAGS_extensions_socket, extensions);
}

Status getExtensions(const std::string& manager_path,
                     ExtensionList& extensions) {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(manager_path);
  if (!status.ok()) {
    return status;
  }

  InternalExtensionList ext_list;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->extensions(ext_list);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Add the extension manager to the list called (core).
  extensions[0] = {"core", kVersion, "0.0.0", kSDKVersion};

  // Convert from Thrift-internal list type to RouteUUID/ExtenionInfo type.
  for (const auto& ext : ext_list) {
    extensions[ext.first] = {ext.second.name,
                             ext.second.version,
                             ext.second.min_sdk_version,
                             ext.second.sdk_version};
  }

  return Status(0, "OK");
}

Status callExtension(const RouteUUID uuid,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return callExtension(
      getExtensionSocket(uuid), registry, item, request, response);
}

Status callExtension(const std::string& extension_path,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(extension_path);
  if (!status.ok()) {
    return status;
  }

  ExtensionResponse ext_response;
  try {
    auto client = EXClient(extension_path);
    client.get()->call(ext_response, registry, item, request);
  }
  catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Convert from Thrift-internal list type to PluginResponse type.
  if (ext_response.status.code == ExtensionCode::EXT_SUCCESS) {
    for (const auto& item : ext_response.response) {
      response.push_back(item);
    }
  }
  return Status(ext_response.status.code, ext_response.status.message);
}

Status startExtensionWatcher(const std::string& manager_path,
                             size_t interval,
                             bool fatal) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::addService(
      std::make_shared<ExtensionWatcher>(manager_path, interval, fatal));
  return Status(0, "OK");
}

Status startExtensionManager() {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return startExtensionManager(FLAGS_extensions_socket);
}

Status startExtensionManager(const std::string& manager_path) {
  // Check if the socket location exists.
  auto status = socketWritable(manager_path);
  if (!status.ok()) {
    return status;
  }

  // Seconds converted to milliseconds, used as a thread interruptible.
  auto latency = atoi(FLAGS_extensions_interval.c_str()) * 1000;
  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::addService(
      std::make_shared<ExtensionManagerWatcher>(manager_path, latency));

  // Start the extension manager thread.
  Dispatcher::addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));
  return Status(0, "OK");
}
}
