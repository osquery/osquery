/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/process.h"
#include "osquery/core/watcher.h"
#include "osquery/extensions/interface.h"
#include "osquery/filesystem/fileops.h"

using namespace osquery::extensions;

namespace fs = boost::filesystem;

namespace osquery {

// Millisecond latency between initializing manager pings.
const size_t kExtensionInitializeLatency = 20;

enum class ExtendableType {
  EXTENSION = 1,
};

using ExtendableTypeSet = std::map<ExtendableType, std::string>;

const std::map<PlatformType, ExtendableTypeSet> kFileExtensions{
    {PlatformType::TYPE_WINDOWS, {{ExtendableType::EXTENSION, ".exe"}}},
    {PlatformType::TYPE_LINUX, {{ExtendableType::EXTENSION, ".ext"}}},
    {PlatformType::TYPE_OSX, {{ExtendableType::EXTENSION, ".ext"}}},
};

CLI_FLAG(bool, disable_extensions, false, "Disable extension API");

CLI_FLAG(string,
         extensions_socket,
         OSQUERY_SOCKET "osquery.em",
         "Path to the extensions UNIX domain socket");

CLI_FLAG(string,
         extensions_autoload,
         OSQUERY_HOME "/extensions.load",
         "Optional path to a list of autoloaded & managed extensions");

CLI_FLAG(string,
         extensions_timeout,
         "3",
         "Seconds to wait for autoloaded extensions");

CLI_FLAG(string,
         extensions_interval,
         "3",
         "Seconds delay between connectivity checks");

SHELL_FLAG(string, extension, "", "Path to a single extension to autoload");

CLI_FLAG(string,
         extensions_require,
         "",
         "Comma-separated list of required extensions");

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

Status applyExtensionDelay(std::function<Status(bool& stop)> predicate) {
  // Make sure the extension manager path exists, and is writable.
  size_t delay = 0;
  // The timeout is given in seconds, but checked interval is microseconds.
  size_t timeout = atoi(FLAGS_extensions_timeout.c_str()) * 1000;
  if (timeout < kExtensionInitializeLatency * 10) {
    timeout = kExtensionInitializeLatency * 10;
  }

  Status status;
  do {
    bool stop = false;
    status = predicate(stop);
    if (stop || status.ok()) {
      break;
    }

    // Increase the total wait detail.
    delay += kExtensionInitializeLatency;
    sleepFor(kExtensionInitializeLatency);
  } while (delay < timeout);
  return status;
}

Status extensionPathActive(const std::string& path, bool use_timeout = false) {
  return applyExtensionDelay(([path, &use_timeout](bool& stop) {
    if (socketExists(path)) {
      try {
        ExtensionStatus status;
        // Create a client with a 2-second receive timeout.
        EXManagerClient client(path, 2 * 1000);
        client.get()->ping(status);
        return Status(0, "OK");
      } catch (const std::exception& /* e */) {
        // Path might exist without a connected extension or extension manager.
      }
    }
    // Only check active once if this check does not allow a timeout.
    if (!use_timeout) {
      stop = true;
    }
    return Status(1, "Extension socket not available: " + path);
  }));
}

ExtensionWatcher::ExtensionWatcher(const std::string& path,
                                   size_t interval,
                                   bool fatal)
    : InternalRunnable("ExtensionWatcher"),
      path_(path),
      interval_(interval),
      fatal_(fatal) {
  // Set the interval to a minimum of 200 milliseconds.
  interval_ = (interval_ < 200) ? 200 : interval_;
}

void ExtensionWatcher::start() {
  // Watch the manager, if the socket is removed then the extension will die.
  // A check for sane paths and activity is applied before the watcher
  // service is added and started.
  while (!interrupted()) {
    watch();
    pauseMilli(interval_);
  }
}

void ExtensionManagerWatcher::start() {
  // Watch each extension.
  while (!interrupted()) {
    watch();
    pauseMilli(interval_);
  }

  // When interrupted, request each extension tear down.
  const auto uuids = RegistryFactory::get().routeUUIDs();
  for (const auto& uuid : uuids) {
    try {
      auto path = getExtensionSocket(uuid);
      EXClient client(path);
      client.get()->shutdown();
    } catch (const std::exception& /* e */) {
      VLOG(1) << "Extension UUID " << uuid << " shutdown request failed";
      continue;
    }
  }
}

void ExtensionWatcher::exitFatal(int return_code) {
  // Exit the extension.
  // We will save the wanted return code and raise an interrupt.
  // This interrupt will be handled by the main thread then join the watchers.
  Initializer::requestShutdown(return_code);
}

void ExtensionWatcher::watch() {
  // Attempt to ping the extension core.
  // This does NOT use pingExtension to avoid the latency checks applied.
  ExtensionStatus status;
  bool core_sane = true;
  if (socketExists(path_)) {
    try {
      EXManagerClient client(path_);
      // Ping the extension manager until it goes down.
      client.get()->ping(status);
    } catch (const std::exception& /* e */) {
      core_sane = false;
    }
  } else {
    // The previously-writable extension socket is not usable.
    core_sane = false;
  }

  if (!core_sane) {
    VLOG(1) << "Extension watcher ending: osquery core has gone away";
    exitFatal(0);
  }

  if (status.code != ExtensionCode::EXT_SUCCESS && fatal_) {
    // The core may be healthy but return a failed ping status.
    exitFatal();
  }
}

void ExtensionManagerWatcher::watch() {
  // Watch the set of extensions, if the socket is removed then the extension
  // will be deregistered.
  const auto uuids = RegistryFactory::get().routeUUIDs();

  ExtensionStatus status;
  for (const auto& uuid : uuids) {
    auto path = getExtensionSocket(uuid);
    auto exists = socketExists(path);

    if (!exists.ok() && failures_[uuid] == 0) {
      // If there was never a failure then this is the first attempt.
      // Allow the extension to be latent and respect the autoload timeout.
      VLOG(1) << "Extension UUID " << uuid << " initial check failed";
      exists = extensionPathActive(path, true);
    }

    // All extensions will have a single failure (and odd use of the counting).
    // If failures get to 2 then the extension will be removed.
    failures_[uuid] = 1;
    if (exists.ok()) {
      try {
        EXClient client(path);
        // Ping the extension until it goes down.
        client.get()->ping(status);
      } catch (const std::exception& /* e */) {
        failures_[uuid] += 1;
        continue;
      }
    } else {
      // Immediate fail non-writable paths.
      failures_[uuid] += 1;
      continue;
    }

    if (status.code != ExtensionCode::EXT_SUCCESS) {
      LOG(INFO) << "Extension UUID " << uuid << " ping failed";
      failures_[uuid] += 1;
    } else {
      failures_[uuid] = 1;
    }
  }

  for (const auto& uuid : failures_) {
    if (uuid.second > 1) {
      LOG(INFO) << "Extension UUID " << uuid.first << " has gone away";
      RegistryFactory::get().removeBroadcast(uuid.first);
      failures_[uuid.first] = 1;
    }
  }
}

void initShellSocket(const std::string& homedir) {
  if (!Flag::isDefault("extensions_socket")) {
    return;
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    osquery::FLAGS_extensions_socket = "\\\\.\\pipe\\shell.em";
  } else {
    osquery::FLAGS_extensions_socket =
        (fs::path(homedir) / "shell.em").make_preferred().string();
  }

  if (extensionPathActive(FLAGS_extensions_socket, false) ||
      !socketExists(FLAGS_extensions_socket, true)) {
    // If there is an existing shell using this socket, or the socket cannot
    // be used (another user using the same path?)
    FLAGS_extensions_socket += std::to_string((uint16_t)rand());
  }
}

void loadExtensions() {
  // Disabling extensions will disable autoloading.
  if (FLAGS_disable_extensions) {
    return;
  }

  // Optionally autoload extensions, sanitize the binary path and inform
  // the osquery watcher to execute the extension when started.
  auto status = loadExtensions(
      fs::path(FLAGS_extensions_autoload).make_preferred().string());
  if (!status.ok()) {
    VLOG(1) << "Could not autoload extensions: " << status.what();
  }
}

static bool isFileSafe(std::string& path, ExtendableType type) {
  boost::trim(path);
  // A 'type name' may be used in verbose log output.
  std::string type_name =
      ((type == ExtendableType::EXTENSION) ? "extension" : "module");
  if (path.size() == 0 || path[0] == '#' || path[0] == ';') {
    return false;
  }

  // Resolve acceptable extension binaries from autoload paths.
  if (isDirectory(path).ok()) {
    VLOG(1) << "Cannot autoload " << type_name << " from directory: " << path;
    return false;
  }

  std::string ext;
  if (isPlatform(PlatformType::TYPE_LINUX)) {
    ext = kFileExtensions.at(PlatformType::TYPE_LINUX).at(type);
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    ext = kFileExtensions.at(PlatformType::TYPE_OSX).at(type);
  } else {
    ext = kFileExtensions.at(PlatformType::TYPE_WINDOWS).at(type);
  }

  // Only autoload file which were safe at the time of discovery.
  // If the binary later becomes unsafe (permissions change) then it will fail
  // to reload if a reload is ever needed.
  fs::path extendable(path);
  // Set the output sanitized path.
  path = extendable.string();
  if (!safePermissions(extendable.parent_path().string(), path, true)) {
    LOG(WARNING) << "Will not autoload " << type_name
                 << " with unsafe directory permissions: " << path;
    return false;
  }

  if (extendable.extension().string() != ext) {
    LOG(WARNING) << "Will not autoload " << type_name << " not ending in '"
                 << ext << "': " << path;
    return false;
  }

  VLOG(1) << "Found autoloadable " << type_name << ": " << path;
  return true;
}

Status loadExtensions(const std::string& loadfile) {
  if (!FLAGS_extension.empty()) {
    // This is a shell-only development flag for quickly loading/using a single
    // extension. It bypasses the safety check.
    Watcher::get().addExtensionPath(FLAGS_extension);
  }

  std::string autoload_paths;
  if (!readFile(loadfile, autoload_paths).ok()) {
    return Status(1, "Failed reading: " + loadfile);
  }

  // The set of binaries to auto-load, after safety is confirmed.
  std::set<std::string> autoload_binaries;
  for (auto& path : osquery::split(autoload_paths, "\n")) {
    if (isDirectory(path)) {
      std::vector<std::string> paths;
      listFilesInDirectory(path, paths, true);
      for (auto& embedded_path : paths) {
        if (isFileSafe(embedded_path, ExtendableType::EXTENSION)) {
          autoload_binaries.insert(std::move(embedded_path));
        }
      }
    } else if (isFileSafe(path, ExtendableType::EXTENSION)) {
      autoload_binaries.insert(path);
    }
  }

  for (const auto& binary : autoload_binaries) {
    // After the path is sanitized the watcher becomes responsible for
    // forking and executing the extension binary.
    Watcher::get().addExtensionPath(binary);
  }
  return Status(0, "OK");
}

Status startExtension(const std::string& name, const std::string& version) {
  return startExtension(name, version, "0.0.0");
}

Status startExtension(const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version) {
  // Tell the registry that this is an extension.
  // When a broadcast is requested this registry should not send core plugins.
  RegistryFactory::get().setExternal();

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
  return Status(0);
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
  auto broadcast = RegistryFactory::get().getBroadcast();
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
    EXManagerClient client(manager_path);
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

  // Now that the UUID is known, try to clean up stale socket paths.
  auto extension_path = getExtensionSocket(ext_status.uuid, manager_path);

  status = socketExists(extension_path, true);
  if (!status) {
    return status;
  }

  // Set the active config and logger plugins. The core will arbitrate if the
  // plugins are not available in the extension's local registry.
  auto& rf = RegistryFactory::get();
  rf.setActive("config", options["config_plugin"].value);
  rf.setActive("logger", options["logger_plugin"].value);
  rf.setActive("distributed", options["distributed_plugin"].value);
  // Set up all lazy registry plugins and the active config/logger plugin.
  rf.setUp();

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
    EXManagerClient client(manager_path);
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
    EXManagerClient client(manager_path);
    client.get()->getQueryColumns(response, query);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Translate response map: {string: string} to a vector: pair(name, type).
  for (const auto& column : response.response) {
    for (const auto& col : column) {
      columns.push_back(std::make_tuple(
          col.first, columnTypeName(col.second), ColumnOptions::DEFAULT));
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
    EXClient client(path);
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
    EXManagerClient client(manager_path);
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
    EXClient client(extension_path);
    client.get()->call(ext_response, registry, item, request);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Convert from Thrift-internal list type to PluginResponse type.
  if (ext_response.status.code == ExtensionCode::EXT_SUCCESS) {
    for (const auto& response_item : ext_response.response) {
      response.push_back(response_item);
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

  // Start a extension watcher, if the manager dies, so should we.
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
  // Check if the socket location is ready for a new Thrift server.
  // We expect the path to be invalid or a removal attempt to succeed.
  auto status = socketExists(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // Seconds converted to milliseconds, used as a thread interruptible.
  auto latency = atoi(FLAGS_extensions_interval.c_str()) * 1000;
  // Start a extension manager watcher, to monitor all registered extensions.
  Dispatcher::addService(
      std::make_shared<ExtensionManagerWatcher>(manager_path, latency));

  // Start the extension manager thread.
  Dispatcher::addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));

  // The shell or daemon flag configuration may require an extension.
  if (!FLAGS_extensions_require.empty()) {
    bool waited = false;
    auto extensions = osquery::split(FLAGS_extensions_require, ",");
    for (const auto& extension : extensions) {
      status = applyExtensionDelay(([extension, &waited](bool& stop) {
        ExtensionList registered_extensions;
        if (getExtensions(registered_extensions).ok()) {
          for (const auto& existing : registered_extensions) {
            if (existing.second.name == extension) {
              return pingExtension(getExtensionSocket(existing.first));
            }
          }
        }

        if (waited) {
          // If we have already waited for the timeout period, stop early.
          stop = true;
        }
        return Status(1, "Extension not autoloaded: " + extension);
      }));

      // A required extension was not loaded.
      waited = true;
      if (!status.ok()) {
        LOG(WARNING) << status.getMessage();
        return status;
      }
    }
  }

  return Status(0, "OK");
}
} // namespace osquery
