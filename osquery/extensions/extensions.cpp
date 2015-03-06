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

using namespace osquery::extensions;

namespace osquery {

const int kWatcherMLatency = 3000;

#ifdef __APPLE__
const std::string kModuleExtension = "dylib";
#else
const std::string kModuleExtension = "so";
#endif

CLI_FLAG(bool, disable_extensions, false, "Disable extension API");

CLI_FLAG(string,
         extensions_socket,
         "/var/osquery/osquery.em",
         "Path to the extensions UNIX domain socket")

CLI_FLAG(string,
         extensions_autoload,
         "",
         "An optional search path for autoloaded & managed extensions")

CLI_FLAG(string,
         modules_autoload,
         "/usr/lib/osquery/modules",
         "Search path for autoloaded registry modules")

/// Alias the extensions_socket (used by core) to an alternate name reserved
/// for extension binaries
EXTENSION_FLAG_ALIAS(std::string, socket, extensions_socket);

void ExtensionWatcher::enter() {
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

void loadExtensions() {
  // Optionally autoload extensions
  auto status = loadExtensions(FLAGS_extensions_autoload);
  if (!status.ok()) {
    LOG(WARNING) << "Could not autoload extensions: " << status.what();
  }
}

void loadModules() {
  auto status = loadModules(FLAGS_modules_autoload);
  if (!status.ok()) {
    LOG(WARNING) << "Modules autoload contains invalid paths";
  }
}

Status loadExtensions(const std::string& paths) {
  // Not implemented: Autoloading extensions given a search path.
  return Status(0, "OK");
}

Status loadModulesFromDirectory(const std::string& dir) {
  std::vector<std::string> modules;
  if (!listFilesInDirectory(dir, modules).ok()) {
    return Status(1, "Cannot read files from " + dir);
  }

  for (const auto& module_path : modules) {
    if (safePermissions(dir, module_path)) {
      if (std::find_end(module_path.begin(),
                        module_path.end(),
                        kModuleExtension.begin(),
                        kModuleExtension.end()) -
              module_path.end() ==
          (kModuleExtension.size() * -1)) {
        // Silently allow module load failures to drop.
        RegistryModuleLoader loader(module_path);
        loader.init();
      }
    }
  }
  return Status(0, "OK");
}

Status loadModules(const std::string& paths) {
  auto status = Status(0, "OK");

  // Split the search path for modules using a ':' delimiter.
  auto search_paths = osquery::split(paths, ":");
  for (auto& path : search_paths) {
    boost::trim(path);
    auto path_status = loadModulesFromDirectory(path);
    if (!path_status.ok()) {
      status = path_status;
    }
  }
  // Return an aggregate failure if any load fails (invalid search path).
  return status;
}

Status startExtension(const std::string& name, const std::string& version) {
  return startExtension(name, version, "0.0.0");
}

Status startExtension(const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version) {
  // No assumptions about how the extensions logs, the first action is to
  // start the extension's registry.
  Registry::setUp();

  auto status =
      startExtensionWatcher(FLAGS_extensions_socket, kWatcherMLatency, true);
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
    Dispatcher::joinServices();
  } catch (const std::exception& e) {
    // The extension manager may shutdown without notifying the extension.
    return Status(0, e.what());
  }

  // An extension will only return on failure.
  return Status(0, "OK");
}

Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version,
                      const std::string& sdk_version) {
  // Make sure the extension manager path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not available: " + manager_path);
  }

  // The Registry broadcast is used as the ExtensionRegistry.
  auto broadcast = Registry::getBroadcast();

  InternalExtensionInfo info;
  info.name = name;
  info.version = version;
  info.sdk_version = sdk_version;
  info.min_sdk_version = min_sdk_version;

  // Register the extension's registry broadcast with the manager.
  ExtensionStatus status;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->registerExtension(status, info, broadcast);
  }
  catch (const std::exception& e) {
    return Status(1, "Extension register failed: " + std::string(e.what()));
  }

  if (status.code != ExtensionCode::EXT_SUCCESS) {
    return Status(status.code, status.message);
  }

  // Now that the uuid is known, try to clean up stale socket paths.
  auto extension_path = getExtensionSocket(status.uuid, manager_path);
  if (pathExists(extension_path).ok()) {
    if (!isWritable(extension_path).ok()) {
      return Status(1, "Cannot write extension socket: " + extension_path);
    }

    if (!remove(extension_path).ok()) {
      return Status(1, "Cannot remove extension socket: " + extension_path);
    }
  }

  // Start the extension's Thrift server
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionRunner>(manager_path, status.uuid));
  VLOG(1) << "Extension (" << name << ", " << status.uuid << ", " << version
          << ", " << sdk_version << ") registered";
  return Status(0, std::to_string(status.uuid));
}

Status queryExternal(const std::string& manager_path,
                     const std::string& query,
                     QueryData& results) {
  // Make sure the extension path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not available: " + manager_path);
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
                               tables::TableColumns& columns) {
  // Make sure the extension path exists, and is writable.
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not available: " + manager_path);
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
                               tables::TableColumns& columns) {
  return getQueryColumnsExternal(FLAGS_extensions_socket, query, columns);
}

Status pingExtension(const std::string& path) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }

  // Make sure the extension path exists, and is writable.
  if (!pathExists(path) || !isWritable(path)) {
    return Status(1, "Extension socket not available: " + path);
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
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not available: " + manager_path);
  }

  InternalExtensionList ext_list;
  try {
    auto client = EXManagerClient(manager_path);
    client.get()->extensions(ext_list);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Add the extension manager to the list called (core).
  extensions[0] = {"core", OSQUERY_VERSION, "0.0.0", OSQUERY_SDK_VERSION};

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
  if (!pathExists(extension_path) || !isWritable(extension_path)) {
    return Status(1, "Extension socket not available: " + extension_path);
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
  if (!pathExists(manager_path) || !isWritable(manager_path)) {
    return Status(1, "Extension manager socket not available: " + manager_path);
  }

  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::getInstance().addService(
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
  if (pathExists(manager_path).ok()) {
    if (!isWritable(manager_path).ok()) {
      return Status(1, "Cannot write extension socket: " + manager_path);
    }

    if (!remove(manager_path).ok()) {
      return Status(1, "Cannot remove extension socket: " + manager_path);
    }
  }

  // Start a extension manager watcher, if the manager dies, so should we.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionManagerWatcher>(manager_path,
                                                kWatcherMLatency));

  // Start the extension manager thread.
  Dispatcher::getInstance().addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));
  return Status(0, "OK");
}
}
